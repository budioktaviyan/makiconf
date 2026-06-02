#!/usr/bin/env bash
set -euo pipefail

JOERN_PORT="${JOERN_PORT:-8080}"
JOERN_URL="http://localhost:${JOERN_PORT}"

send_response() {
  local response="$1"
  printf '%s\n' "$response"
}

joern_query() {
  local query="$1"
  local timeout="${2:-120}"
  local result exit_code=0
  result=$(curl -sf --max-time "$timeout" -X POST "${JOERN_URL}/query-sync" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg q "$query" '{query: $q}')" 2>&1) || exit_code=$?

  if [ $exit_code -ne 0 ]; then
    printf '%s' "Joern server not running or query timed out. Start with: joern --server"
    return 1
  fi

  local stdout stderr
  stdout=$(printf '%s' "$result" | jq -r '.stdout // empty')
  stderr=$(printf '%s' "$result" | jq -r '.stderr // empty')

  if [ -n "$stderr" ] && [ "$stderr" != "null" ] && [ "$stderr" != "" ]; then
    printf '%s' "$stderr"
    return 1
  fi

  printf '%s' "$stdout"
}

handle_initialize() {
  local id="$1"
  local resp
  resp=$(cat <<EOF
{"jsonrpc":"2.0","id":$id,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"taint-mcp","version":"2.0.0"}}}
EOF
  )
  send_response "$resp"
}

handle_tools_list() {
  local id="$1"
  local resp
  resp=$(cat <<'TOOLSEOF'
{"jsonrpc":"2.0","id":__ID__,"result":{"tools":[{"name":"load_cpg","description":"Import C/C++ source into Joern for analysis. Call before using other tools. Automatically runs the dataflow overlay needed for taint tracking.\n\nAccepts either:\n- Source code: a .c file or directory (uses importCode, parses from scratch)\n- Pre-built CPG: a .bin or .bin.zip file created by joern-parse (uses importCpg, much faster for large projects)\n\nFor large projects, pre-build with: joern-parse /path/to/src -o project.bin\n\nExamples:\n  {\"path\": \"/home/user/project/src/parser.c\"}\n  {\"path\": \"/home/user/project/cpg.bin\"}\n  {\"path\": \"/home/user/project/src\", \"name\": \"myapp\"}","inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"Absolute path to C/C++ source directory, source file, or pre-built cpg.bin / cpg.bin.zip."},"name":{"type":"string","description":"Optional project name for the CPG"}},"required":["path"]}},{"name":"trace_forward","description":"Track where data from a variable flows to. Finds paths to dangerous sinks (memcpy, system, printf, free, etc).\n\nThe variable should be an identifier visible at the given line. Works best with function parameters and local variables.\n\nExamples:\n  {\"variable\": \"buf\", \"file\": \"parser.c\", \"line\": 42}\n  {\"variable\": \"user_input\", \"file\": \"main.c\", \"line\": 10}","inputSchema":{"type":"object","properties":{"variable":{"type":"string","description":"Variable name to trace (exact identifier name)"},"file":{"type":"string","description":"Source filename (basename like 'main.c' or path)"},"line":{"type":"integer","description":"Line number where the variable appears"}},"required":["variable","file","line"]}},{"name":"trace_backward","description":"Track where data in a variable originates from. Finds paths from sources (function params, globals, return values of calls) to the variable.\n\nExamples:\n  {\"variable\": \"buf\", \"file\": \"handler.c\", \"line\": 87}\n  {\"variable\": \"len\", \"file\": \"parse.c\", \"line\": 33}","inputSchema":{"type":"object","properties":{"variable":{"type":"string","description":"Variable name to trace (exact identifier name)"},"file":{"type":"string","description":"Source filename (basename like 'main.c' or path)"},"line":{"type":"integer","description":"Line number where the variable appears"}},"required":["variable","file","line"]}},{"name":"trace_param","description":"Track all flows from a function parameter to sinks or through callees. More reliable than trace_forward for function parameters.\n\nExamples:\n  {\"function\": \"anetSetError\", \"param_index\": 1}\n  {\"function\": \"processCommand\", \"param_index\": 1}","inputSchema":{"type":"object","properties":{"function":{"type":"string","description":"Function name containing the parameter"},"param_index":{"type":"integer","description":"Parameter index (1-based: 1 = first param, 2 = second, etc)"}},"required":["function","param_index"]}},{"name":"list_functions","description":"List all user-defined functions in the loaded CPG with their signatures and line numbers.\n\nExamples:\n  {}\n  {\"filter\": \"accept\"}","inputSchema":{"type":"object","properties":{"filter":{"type":"string","description":"Optional regex to filter function names"}}}},{"name":"list_calls","description":"List calls to a specific function, or list all calls to dangerous sink functions if no name given.\n\nExamples:\n  {\"name\": \"memcpy\"}\n  {\"name\": \"snprintf\"}\n  {}","inputSchema":{"type":"object","properties":{"name":{"type":"string","description":"Function name to find calls to. If omitted, lists calls to common dangerous sinks (memcpy, strcpy, sprintf, system, free, etc)."}}}},{"name":"cpg_query","description":"Run a CPGQL query on the Code Property Graph. Full Joern query language.\n\nCommon patterns:\n  cpg.method.name.l                                              — list all functions\n  cpg.call.name(\"memcpy\").code.l                                 — find calls\n  cpg.method.name(\"main\").parameter.l                            — function params\n  cpg.method.name(\"f\").callee.name.l                             — callees of f\n  cpg.method.name(\"f\").caller.name.l                             — callers of f\n  cpg.identifier.name(\"x\").inCall.code.l                         — usages of x\n  {val src = cpg.method.name(\"f\").parameter;                     — taint from param\n   val sink = cpg.call.name(\"memcpy\").argument;                    to memcpy\n   sink.reachableByFlows(src).p}","inputSchema":{"type":"object","properties":{"query":{"type":"string","description":"CPGQL query string"}},"required":["query"]}}]}}
TOOLSEOF
  )
  resp="${resp/__ID__/$id}"
  send_response "$resp"
}

handle_tool_call() {
  local id="$1"
  local tool_name="$2"
  local arguments="$3"
  local result_text is_error=false

  case "$tool_name" in
    "load_cpg")
      local path name cpgql
      path=$(printf '%s' "$arguments" | jq -r '.path // empty')
      name=$(printf '%s' "$arguments" | jq -r '.name // empty')

      if [ -z "$path" ]; then
        result_text="Error: path is required."
        is_error=true
      else
        # Detect pre-built CPG vs source code
        if [[ "$path" == *.bin || "$path" == *.bin.zip ]]; then
          if [ -n "$name" ]; then
            cpgql="importCpg(\"$path\", \"$name\")"
          else
            cpgql="importCpg(\"$path\")"
          fi
        else
          if [ -n "$name" ]; then
            cpgql="importCode(\"$path\", \"$name\")"
          else
            cpgql="importCode(\"$path\")"
          fi
        fi
        local output exit_code=0
        output=$(joern_query "$cpgql" 300) || exit_code=$?
        if [ $exit_code -ne 0 ]; then
          result_text="$output"
          is_error=true
        else
          local df_output df_exit=0
          df_output=$(joern_query "run.ossdataflow" 300) || df_exit=$?
          if [ $df_exit -ne 0 ]; then
            result_text="CPG loaded for: $path (WARNING: dataflow overlay failed - taint tracking may not work)"$'\n'"$output"$'\n'"Dataflow error: $df_output"
          else
            result_text="CPG loaded for: $path"$'\n'"$output"
          fi
        fi
      fi
      ;;

    "trace_forward")
      local var file line
      var=$(printf '%s' "$arguments" | jq -r '.variable // empty')
      file=$(printf '%s' "$arguments" | jq -r '.file // empty')
      line=$(printf '%s' "$arguments" | jq -r '.line // empty')

      if [ -z "$var" ] || [ -z "$file" ] || [ -z "$line" ]; then
        result_text="Error: variable, file, and line are required."
        is_error=true
      else
        local basename="${file##*/}"
        local sinks='memcpy|strcpy|strncpy|strcat|strncat|sprintf|snprintf|vsnprintf|printf|fprintf|vfprintf|system|execve|execl|execlp|execvp|popen|gets|fgets|scanf|sscanf|fscanf|read|recv|recvfrom|write|send|sendto|free|realloc|malloc|calloc'
        local cpgql
        cpgql="{ val sources = cpg.identifier.name(\"${var}\").where(_.lineNumber(${line})).where(_.file.name(\".*${basename}\")); val fallback = cpg.call.argument.where(_.code(\".*${var}.*\")).where(_.lineNumber(${line})).where(_.file.name(\".*${basename}\")); val s = if(sources.nonEmpty) sources else fallback; val sinks = cpg.call.name(\"${sinks}\").argument; sinks.reachableByFlows(s).p }"
        local output exit_code=0
        output=$(joern_query "$cpgql") || exit_code=$?
        if [ $exit_code -ne 0 ]; then
          result_text="$output"
          is_error=true
        elif [ -z "$output" ] || [ "$output" = "List()" ] || [[ "$output" == *"List()"* && ! "$output" == *"┌"* ]]; then
          result_text="No forward taint flows found from '$var' at $file:$line to known sinks."
        else
          result_text="Forward taint flows from '$var' at $file:$line:"$'\n\n'"$output"
        fi
      fi
      ;;

    "trace_backward")
      local var file line
      var=$(printf '%s' "$arguments" | jq -r '.variable // empty')
      file=$(printf '%s' "$arguments" | jq -r '.file // empty')
      line=$(printf '%s' "$arguments" | jq -r '.line // empty')

      if [ -z "$var" ] || [ -z "$file" ] || [ -z "$line" ]; then
        result_text="Error: variable, file, and line are required."
        is_error=true
      else
        local basename="${file##*/}"
        local cpgql
        cpgql="{ val targets = cpg.identifier.name(\"${var}\").where(_.lineNumber(${line})).where(_.file.name(\".*${basename}\")); val fallback = cpg.call.name(\"${var}\").where(_.lineNumber(${line})).where(_.file.name(\".*${basename}\")); val t = if(targets.nonEmpty) targets else fallback; val sources = cpg.method.parameter ++ cpg.call.argument; t.reachableByFlows(sources).p }"
        local output exit_code=0
        output=$(joern_query "$cpgql") || exit_code=$?
        if [ $exit_code -ne 0 ]; then
          result_text="$output"
          is_error=true
        elif [ -z "$output" ] || [ "$output" = "List()" ] || [[ "$output" == *"List()"* && ! "$output" == *"┌"* ]]; then
          result_text="No backward taint flows found to '$var' at $file:$line."
        else
          result_text="Backward taint flows to '$var' at $file:$line:"$'\n\n'"$output"
        fi
      fi
      ;;

    "trace_param")
      local func param_idx
      func=$(printf '%s' "$arguments" | jq -r '.function // empty')
      param_idx=$(printf '%s' "$arguments" | jq -r '.param_index // empty')

      if [ -z "$func" ] || [ -z "$param_idx" ]; then
        result_text="Error: function and param_index are required."
        is_error=true
      else
        local sinks='memcpy|strcpy|strncpy|strcat|strncat|sprintf|snprintf|vsnprintf|printf|fprintf|vfprintf|system|execve|execl|execlp|execvp|popen|gets|fgets|scanf|sscanf|fscanf|read|recv|recvfrom|write|send|sendto|free|realloc|malloc|calloc'
        local cpgql
        cpgql="{ val sources = cpg.method.name(\"${func}\").parameter.index(${param_idx}); val sinks = cpg.call.name(\"${sinks}\").argument; sinks.reachableByFlows(sources).p }"
        local output exit_code=0
        output=$(joern_query "$cpgql") || exit_code=$?
        if [ $exit_code -ne 0 ]; then
          result_text="$output"
          is_error=true
        elif [ -z "$output" ] || [ "$output" = "List()" ] || [[ "$output" == *"List()"* && ! "$output" == *"┌"* ]]; then
          result_text="No taint flows found from parameter $param_idx of '$func' to known sinks."
        else
          result_text="Taint flows from parameter $param_idx of '$func':"$'\n\n'"$output"
        fi
      fi
      ;;

    "list_functions")
      local filter
      filter=$(printf '%s' "$arguments" | jq -r '.filter // empty')

      local cpgql
      if [ -n "$filter" ]; then
        cpgql="cpg.method.name(\".*${filter}.*\").where(_.isExternal(false)).map(m => s\"\${m.filename}:\${m.lineNumber.getOrElse(0)} \${m.signature}\").l.sorted.mkString(\"\\n\")"
      else
        cpgql="cpg.method.where(_.isExternal(false)).map(m => s\"\${m.filename}:\${m.lineNumber.getOrElse(0)} \${m.signature}\").l.sorted.mkString(\"\\n\")"
      fi
      local output exit_code=0
      output=$(joern_query "$cpgql") || exit_code=$?
      if [ $exit_code -ne 0 ]; then
        result_text="$output"
        is_error=true
      elif [ -z "$output" ]; then
        result_text="No functions found."
      else
        result_text="$output"
      fi
      ;;

    "list_calls")
      local name
      name=$(printf '%s' "$arguments" | jq -r '.name // empty')

      local cpgql
      if [ -n "$name" ]; then
        cpgql="cpg.call.name(\"${name}\").map(c => s\"\${c.file.name.headOption.getOrElse(\"?\")}:\${c.lineNumber.getOrElse(0)} \${c.code}\").l.mkString(\"\\n\")"
      else
        local sinks='memcpy|strcpy|strncpy|strcat|strncat|sprintf|snprintf|vsnprintf|printf|fprintf|vfprintf|system|execve|execl|execlp|execvp|popen|gets|fgets|scanf|sscanf|fscanf|free|realloc'
        cpgql="cpg.call.name(\"${sinks}\").map(c => s\"\${c.file.name.headOption.getOrElse(\"?\")}:\${c.lineNumber.getOrElse(0)} \${c.code}\").l.mkString(\"\\n\")"
      fi
      local output exit_code=0
      output=$(joern_query "$cpgql") || exit_code=$?
      if [ $exit_code -ne 0 ]; then
        result_text="$output"
        is_error=true
      elif [ -z "$output" ]; then
        result_text="No calls found."
      else
        result_text="$output"
      fi
      ;;

    "cpg_query")
      local query
      query=$(printf '%s' "$arguments" | jq -r '.query // empty')

      if [ -z "$query" ]; then
        result_text="Error: query is required."
        is_error=true
      else
        local output exit_code=0
        output=$(joern_query "$query") || exit_code=$?
        if [ $exit_code -ne 0 ]; then
          result_text="$output"
          is_error=true
        else
          result_text="$output"
        fi
      fi
      ;;

    *)
      local err_resp
      err_resp=$(jq -cn --argjson id "$id" '{jsonrpc:"2.0",id:$id,error:{code:-32602,message:"Unknown tool"}}')
      send_response "$err_resp"
      return
      ;;
  esac

  local resp
  resp=$(jq -cn --argjson id "$id" --arg text "$result_text" --argjson err "$is_error" \
    '{jsonrpc:"2.0",id:$id,result:{content:[{type:"text",text:$text}],isError:$err}}')
  send_response "$resp"
}

while IFS= read -r line; do
  line="${line%%$'\r'}"
  if [ -z "$line" ]; then
    continue
  fi

  body="$line"

  method=$(printf '%s' "$body" | jq -r '.method // empty')
  id=$(printf '%s' "$body" | jq -r '.id // empty')

  case "$method" in
    "initialize")
      handle_initialize "$id"
      ;;
    "notifications/initialized")
      ;;
    "tools/list")
      handle_tools_list "$id"
      ;;
    "tools/call")
      tool_name=$(printf '%s' "$body" | jq -r '.params.name')
      tool_args=$(printf '%s' "$body" | jq -c '.params.arguments // {}')
      handle_tool_call "$id" "$tool_name" "$tool_args"
      ;;
    "ping")
      send_response "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{}}"
      ;;
    *)
      if [ -n "$id" ]; then
        err_resp=$(jq -cn --argjson id "$id" '{jsonrpc:"2.0",id:$id,error:{code:-32601,message:"Method not found"}}')
        send_response "$err_resp"
      fi
      ;;
  esac
done
