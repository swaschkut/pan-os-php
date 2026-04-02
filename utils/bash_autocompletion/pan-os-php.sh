#!/usr/bin/env bash
# pan-os-php shell completion — bash (≥5) and zsh
#
# Sourced by both shells; detects the active shell at load time and
# registers completions using the appropriate mechanism:
#   bash  →  complete -F __pan_os_php  pan-os-php
#   zsh   →  compdef  _pan_os_php      pan-os-php
#
# ISC License
# Copyright (c) 2014-2018, Palo Alto Networks Inc.
# Copyright (c) 2019, Palo Alto Networks Inc.
# Copyright (c) 2024, Sven Waschkut - pan-os-php@waschkut.net

# ── Locate the JSON data file regardless of shell ─────────────────────────────
# Resolved via readlink so symlinks in /etc/bash_completion.d/ work correctly.
if [[ -n "${ZSH_VERSION}" ]]; then
    _pan_os_php_script="${${(%):-%x}:A}"
else
    _pan_os_php_script="$(readlink -f "${BASH_SOURCE[0]}")"
fi
_pan_os_php_dir="$(dirname "${_pan_os_php_script}")"
_pan_os_php_json="${_pan_os_php_dir}/../lib/util_action_filter.json"

# ══════════════════════════════════════════════════════════════════════════════
#  ZSH — compdef-based completion
# ══════════════════════════════════════════════════════════════════════════════
if [[ -n "${ZSH_VERSION}" ]]; then

_pan_os_php() {
    local json_file="${_pan_os_php_json}"
    local cur="${words[CURRENT]}"

    # ── Find type= already on the command line ─────────────────────────────
    local type_val=""
    local w
    for w in "${words[@]}"; do
        case "$w" in
            type=*|\'type=*) type_val="${w#\'}" ; type_val="${type_val#type=}" ; break ;;
        esac
    done

    # ── Build set of already-used arguments (to avoid repeating them) ──────
    local -a used
    for w in "${words[@]}"; do
        [[ "$w" == *=* ]]  && used+=("${w%%=*}=")
        [[ "$w" == help || "$w" == listactions || "$w" == listfilters ||
           "$w" == version || "$w" == stats   || "$w" == debugapi    ||
           "$w" == loadpanoramapushedconfig ]] && used+=("$w")
    done

    # ── Full standard argument list ────────────────────────────────────────
    local -a std_args
    std_args=(
        type= in= out= actions= filter= location= loadplugin= template=
        apitimeout= outputformatset=
        help listactions listfilters version stats debugapi
        loadpanoramapushedconfig
        shadow-json shadow-apikeyhidden shadow-apikeynohidden shadow-apikeynosave
        shadow-disableoutputformatting shadow-displaycurlrequest
        shadow-enablexmlduplicatesdeletion shadow-ignoreinvalidaddressobjects
        shadow-reducexml shadow-bpjsonfile shadow-displayxmlnode
        shadow-loaddghierarchy shadow-loadreduce shadow-nojson shadow-saseapiqa
    )

    # Remove already-used args from default suggestion list
    local -a remaining_args
    local arg
    for arg in "${std_args[@]}"; do
        [[ " ${used[*]} " == *" ${arg} "* ]] || remaining_args+=("$arg")
    done

    # ── Vendor and phase option lists ──────────────────────────────────────
    local -a vendors phases
    vendors=(ciscoasa netscreen sonicwall sophos ciscoswitch ciscoisr fortinet
             srx cp-r80 cp cp-beta huawei stonesoft sidewinder sophosxg)
    phases=(p1-marker rule-marker p2-generator report-generator p3-cloner
            rule-cloner p5-activation rule-activation p6-cleaner rule-cleaner)

    # ── Dispatch on the token currently being typed ────────────────────────
    case "${cur}" in

        type=*)
            local val="${cur#type=}"
            local -a types
            types=(${(f)"$(jq -r 'keys[]' "${json_file}" 2>/dev/null)"})
            local -a suggestions
            local t
            for t in "${types[@]}"; do
                [[ "${t}" == ${val}* ]] && suggestions+=("type=${t}")
            done
            compadd -S ' ' -- "${suggestions[@]}"
            ;;

        \'actions=*|actions=*)
            # Strip leading single-quote if present
            local raw="${cur#\'}"
            local val="${raw#actions=}"
            local quote_prefix=""
            [[ "${cur}" == \'* ]] && quote_prefix="'"

            if [[ -n "${type_val}" ]]; then
                local -a acts
                acts=(${(f)"$(jq -r \
                    ".\"${type_val}\" | select(.action != null) | .action | keys[]" \
                    "${json_file}" 2>/dev/null)"})

                # Determine context: are we after a '/' (chained action) or ':' (action args)?
                # Action syntax: actions=act1:arg1,arg2|arg3/act2:arg1/act3
                # Find the last segment after the last '/'
                local last_segment="${val##*/}"
                local prefix_before=""
                if [[ "${val}" == */* ]]; then
                    prefix_before="${val%/*}/"
                fi

                if [[ "${last_segment}" == *:* ]]; then
                    # ── After ':' — complete action arguments ──────────────
                    local act_name="${last_segment%%:*}"
                    local arg_part="${last_segment#*:}"

                    # Get action arg info from JSON (choices arrays and arg names)
                    local -a arg_suggestions
                    local args_json
                    args_json="$(jq -r \
                        ".\"${type_val}\".action.\"${act_name}\".args // empty" \
                        "${json_file}" 2>/dev/null)"

                    if [[ -n "${args_json}" ]]; then
                        # Collect all choices from all args
                        local -a choices
                        choices=(${(f)"$(echo "${args_json}" | jq -r \
                            '[.[] | select(.choices != null) | .choices[]] | unique | .[]' \
                            2>/dev/null)"})

                        # Collect arg names with their types as hints
                        local -a arg_names
                        arg_names=(${(f)"$(echo "${args_json}" | jq -r \
                            'to_entries[] | .key' 2>/dev/null)"})

                        # Determine what's already been provided (split on , and |)
                        local last_arg="${arg_part##*[,|]}"

                        # Build the fixed prefix up to last delimiter
                        local arg_prefix_before=""
                        if [[ "${arg_part}" == *,* || "${arg_part}" == *\|* ]]; then
                            # Everything up to and including the last , or |
                            arg_prefix_before="${arg_part%[,|]*}"
                            # Re-add the delimiter character
                            local delim_char="${arg_part:${#arg_prefix_before}:1}"
                            arg_prefix_before="${arg_prefix_before}${delim_char}"
                        fi

                        local full_prefix="${quote_prefix}actions=${prefix_before}${act_name}:${arg_prefix_before}"

                        if [[ ${#choices[@]} -gt 0 ]]; then
                            local -a suggestions
                            local c
                            for c in "${choices[@]}"; do
                                [[ "${c}" == ${last_arg}* ]] && \
                                    suggestions+=("${full_prefix}${c}")
                            done
                            compadd -S '' -- "${suggestions[@]}"
                        else
                            # No choices — show arg names as hints
                            local -a suggestions
                            local n
                            for n in "${arg_names[@]}"; do
                                [[ "${n}" == ${last_arg}* ]] && \
                                    suggestions+=("${full_prefix}${n}")
                            done
                            compadd -S '' -- "${suggestions[@]}"
                        fi
                    fi

                elif [[ "${val}" == */ ]]; then
                    # ── Right after '/' — suggest next action name ─────────
                    local -a suggestions
                    local a
                    for a in "${acts[@]}"; do
                        suggestions+=("${quote_prefix}actions=${prefix_before}${a}")
                    done
                    compadd -S '' -- "${suggestions[@]}"

                else
                    # ── Completing an action name (possibly after '/') ─────
                    local -a suggestions
                    local a
                    for a in "${acts[@]}"; do
                        [[ "${a}" == ${last_segment}* ]] && \
                            suggestions+=("${quote_prefix}actions=${prefix_before}${a}")
                    done
                    compadd -S '' -- "${suggestions[@]}"
                fi
            fi
            ;;

        \'filter=*|filter=*)
            # Strip leading single-quote if present
            local raw="${cur#\'}"
            local val="${raw#filter=}"
            local quote_prefix=""
            [[ "${cur}" == \'* ]] && quote_prefix="'"

            if [[ -n "${type_val}" ]]; then
                local -a filts
                filts=(${(f)"$(jq -r \
                    ".\"${type_val}\" | select(.filter != null) | .filter | keys[]" \
                    "${json_file}" 2>/dev/null)"})

                # ── Filter syntax: (prop operator arg) and (prop2 operator2) ──
                # We need to figure out where we are in the expression.

                # Find the last opening '(' that hasn't been closed
                local inside_paren=""
                local paren_content=""
                local before_paren=""
                local depth=0
                local i char last_open_pos=0

                for (( i=0; i<${#val}; i++ )); do
                    char="${val:$i:1}"
                    if [[ "${char}" == "(" ]]; then
                        (( depth++ ))
                        last_open_pos=$(( i + 1 ))
                    elif [[ "${char}" == ")" ]]; then
                        (( depth-- ))
                    fi
                done

                if (( depth > 0 )); then
                    # We're inside an unclosed parenthesis
                    inside_paren="yes"
                    paren_content="${val:$last_open_pos}"
                    before_paren="${val:0:$last_open_pos}"
                fi

                local full_prefix="${quote_prefix}filter=${before_paren}"

                if [[ -z "${val}" || "${val}" == "(" ]]; then
                    # ── Empty or just '(' — suggest '(' then filter props ──
                    if [[ -z "${val}" ]]; then
                        compadd -S '' -- "${quote_prefix}filter=("
                    else
                        # Just typed '(' — suggest filter property names
                        local -a suggestions
                        local f
                        for f in "${filts[@]}"; do
                            suggestions+=("${full_prefix}${f}")
                        done
                        compadd -S ' ' -- "${suggestions[@]}"
                    fi

                elif [[ "${inside_paren}" == "yes" ]]; then
                    # We're inside a parenthesized expression
                    # Split paren_content into words
                    local -a pwords
                    pwords=("${(@s/ /)paren_content}")

                    # Remove empty elements
                    local -a pw_clean
                    local pw
                    for pw in "${pwords[@]}"; do
                        [[ -n "${pw}" ]] && pw_clean+=("${pw}")
                    done

                    local nwords=${#pw_clean[@]}

                    if (( nwords == 0 )); then
                        # Just '(' with nothing after — suggest filter properties
                        local -a suggestions
                        local f
                        for f in "${filts[@]}"; do
                            suggestions+=("${full_prefix}${f}")
                        done
                        compadd -S ' ' -- "${suggestions[@]}"

                    elif (( nwords == 1 )) && [[ "${paren_content}" != *" " ]]; then
                        # Typing a filter property name — partial match
                        local partial="${pw_clean[1]}"
                        local -a suggestions
                        local f
                        for f in "${filts[@]}"; do
                            [[ "${f}" == ${partial}* ]] && \
                                suggestions+=("${full_prefix}${f}")
                        done
                        compadd -S ' ' -- "${suggestions[@]}"

                    elif (( nwords == 1 )) && [[ "${paren_content}" == *" " ]]; then
                        # Property typed, space after — suggest operators
                        local prop="${pw_clean[1]}"
                        local -a ops
                        ops=(${(f)"$(jq -r \
                            ".\"${type_val}\".filter.\"${prop}\".operators // empty | keys[]" \
                            "${json_file}" 2>/dev/null)"})
                        if [[ ${#ops[@]} -gt 0 ]]; then
                            local -a suggestions
                            local o
                            for o in "${ops[@]}"; do
                                suggestions+=("${full_prefix}${prop} ${o}")
                            done
                            compadd -S '' -- "${suggestions[@]}"
                        fi

                    elif (( nwords == 2 )) && [[ "${paren_content}" != *" " ]]; then
                        # Typing an operator — partial match
                        local prop="${pw_clean[1]}"
                        local partial_op="${pw_clean[2]}"
                        local -a ops
                        ops=(${(f)"$(jq -r \
                            ".\"${type_val}\".filter.\"${prop}\".operators // empty | keys[]" \
                            "${json_file}" 2>/dev/null)"})
                        local -a suggestions
                        local o
                        for o in "${ops[@]}"; do
                            [[ "${o}" == ${partial_op}* ]] && \
                                suggestions+=("${full_prefix}${prop} ${o}")
                        done
                        # Check if any matching operator takes no arg — if so, suffix with ')'
                        # Otherwise suffix with space for the arg
                        compadd -S '' -- "${suggestions[@]}"

                    elif (( nwords >= 2 )); then
                        # Operator typed — check if it takes an arg
                        local prop="${pw_clean[1]}"
                        local op="${pw_clean[2]}"
                        local takes_arg
                        takes_arg="$(jq -r \
                            ".\"${type_val}\".filter.\"${prop}\".operators.\"${op}\".arg // false" \
                            "${json_file}" 2>/dev/null)"

                        if [[ "${takes_arg}" == "true" ]]; then
                            if (( nwords == 2 )) && [[ "${paren_content}" == *" " ]]; then
                                # After operator+space — hint that an argument is needed, then ')'
                                compadd -S ')' -- "${full_prefix}${prop} ${op} "
                            else
                                # Argument is being typed or was typed — suggest closing ')'
                                local arg_part="${paren_content#* ${op} }"
                                compadd -S '' -- "${full_prefix}${prop} ${op} ${arg_part})"
                            fi
                        else
                            # No arg — close with ')'
                            compadd -S '' -- "${full_prefix}${prop} ${op})"
                        fi
                    fi

                else
                    # We're outside parentheses — suggest 'and'/'or' connectors or '('
                    # Check if val ends with ')' possibly with trailing space
                    local trimmed="${val%%[[:space:]]}"
                    if [[ "${val}" == *")" || "${val}" == *") " || "${val}" == *")  " ]]; then
                        # After a closed expression — suggest connectors
                        local base="${val%%[[:space:]]#}"
                        # Normalize: ensure single space after last ')'
                        local stripped="${val%%)#*})}"
                        # Suggest 'and (' or 'or ('
                        local -a suggestions
                        suggestions=(
                            "${quote_prefix}filter=${val}and ("
                            "${quote_prefix}filter=${val}or ("
                        )
                        compadd -S '' -- "${suggestions[@]}"
                    elif [[ "${val}" == *"and " || "${val}" == *"or " ]]; then
                        # After connector — suggest '('
                        compadd -S '' -- "${quote_prefix}filter=${val}("
                    elif [[ "${val}" == *"and (" || "${val}" == *"or (" ]]; then
                        # After connector+open-paren — suggest filter properties
                        local -a suggestions
                        local f
                        for f in "${filts[@]}"; do
                            suggestions+=("${quote_prefix}filter=${val}${f}")
                        done
                        compadd -S ' ' -- "${suggestions[@]}"
                    else
                        # Fallback — offer filter property names
                        local -a suggestions
                        local f
                        for f in "${filts[@]}"; do
                            [[ "${f}" == ${val}* ]] && \
                                suggestions+=("${quote_prefix}filter=${f}")
                        done
                        compadd -S ' ' -- "${suggestions[@]}"
                    fi
                fi
            fi
            ;;

        in=*|out=*|loadplugin=*|file=*|file1=*|file2=*)
            local prefix="${cur%%=*}="
            local fpath="${cur#*=}"
            # Use zsh globbing for file completion; (N) = null-glob (no error on no match)
            local -a matches
            matches=(${~fpath}*(N) ${~fpath}*(-/N))
            compadd -p "${prefix}" -S '' -f -- "${matches[@]}"
            ;;

        vendor=*)
            local val="${cur#vendor=}"
            local -a suggestions
            local v
            for v in "${vendors[@]}"; do
                [[ "${v}" == ${val}* ]] && suggestions+=("vendor=${v}")
            done
            compadd -S ' ' -- "${suggestions[@]}"
            ;;

        phase=*)
            local val="${cur#phase=}"
            local -a suggestions
            local p
            for p in "${phases[@]}"; do
                [[ "${p}" == ${val}* ]] && suggestions+=("phase=${p}")
            done
            compadd -S ' ' -- "${suggestions[@]}"
            ;;

        # Free-form values — no completions, just don't error
        location=*|template=*|apitimeout=*|outputformatset=*|cluster=*|\
        project=*|tenantid=*|region=*|routetable=*|mapping=*|\
        filter-nameattribute=*|filter-node=*|filter-xpath=*|filter-text=*)
            ;;

        *)
            # Suggest context-specific argument set based on type
            local -a context_args
            case "${type_val}" in
                vendor-migration)
                    context_args=(type= in= out= file= help vendor= routetable= mapping=)
                    ;;
                diff)
                    context_args=(type= in= help file1= file2=)
                    ;;
                appid-toolbox)
                    context_args=(type= in= out= help phase=)
                    ;;
                gcp)
                    context_args=(type= in= out= actions= cluster= project= tenantid= region=)
                    ;;
                xpath)
                    context_args=(type= in= filter-nameattribute= filter-node=
                                  filter-xpath= filter-text= display-fullxpath
                                  display-nameattribute display-xmlnode display-xmllineno)
                    ;;
                *)
                    context_args=("${remaining_args[@]}")
                    ;;
            esac
            # Filter against what user has typed so far
            local -a suggestions
            local a
            for a in "${context_args[@]}"; do
                [[ "${a}" == ${cur}* ]] && suggestions+=("${a}")
            done
            compadd -S '' -- "${suggestions[@]}"
            ;;
    esac
}

# Register with compdef; if compinit hasn't been called yet (e.g. non-interactive
# context), initialise it first so compdef is available.
if (( ! ${+functions[compdef]} )); then
    autoload -Uz compinit && compinit -C
fi
compdef _pan_os_php pan-os-php

# ══════════════════════════════════════════════════════════════════════════════
#  BASH — complete-based completion  (bash ≥ 5)
# ══════════════════════════════════════════════════════════════════════════════
elif [[ -n "${BASH_VERSION}" ]]; then

    if [[ "${BASH_VERSINFO[0]}" -lt 5 ]]; then
        echo "pan-os-php completion requires bash ≥ 5 (have ${BASH_VERSION})" >&2
        return 1
    fi

__pan_os_php() {
    local cur prev prev2 words cword
    local IFS=$'\n'

    _get_comp_words_by_ref cur prev

    declare -a arguments
    declare -a checkArray
    declare -a actions filters vendor

    arguments=(
        'type=' 'in=' 'out=' 'actions=' 'filter=' 'location=' 'loadplugin=' 'help'
        'listactions' 'listfilters' 'debugapi' 'apitimeout='
        'shadow-apikeyhidden' 'shadow-apikeynohidden' 'shadow-apikeynosave'
        'shadow-disableoutputformatting' 'shadow-displaycurlrequest'
        'shadow-enablexmlduplicatesdeletion'
        'shadow-ignoreinvalidaddressobjects' 'shadow-json' 'shadow-reducexml'
        'shadow-bpjsonfile' 'shadow-displayxmlnode' 'shadow-loaddghierarchy'
        'shadow-loadreduce' 'shadow-nojson' 'shadow-saseapiqa'
        'outputformatset='
        'stats' 'template=' 'version'
    )

    arguments_migration=('type=' 'in=' 'out=' 'file=' 'help' 'vendor=' 'routetable=' 'mapping=')
    arguments_diff=('type=' 'in=' 'help' 'file1=' 'file2=')
    arguments_appidtoolbox=('type=' 'in=' 'out=' 'help' 'phase=')
    arguments_gcp=('type=' 'in=' 'out=' 'cluster=' 'project=' 'tenantid=' 'actions=' 'region=')
    arguments_xpath=('type=' 'in=' 'filter-nameattribute=' 'filter-node=' 'filter-xpath='
                     'filter-text=' 'display-fullxpath' 'display-nameattribute'
                     'display-xmlnode' 'display-xmllineno')

    arguments_appidtoolbox_phase=(
        'p1-marker' 'rule-marker' 'p2-generator' 'report-generator' 'p3-cloner'
        'rule-cloner' 'p5-activation' 'rule-activation' 'p6-cleaner' 'rule-cleaner'
    )

    vendor=(ciscoasa netscreen sonicwall sophos ciscoswitch ciscoisr fortinet srx
            cp-r80 cp cp-beta huawei stonesoft sidewinder sophosxg)

    local DIR="${_pan_os_php_dir}"
    local jsonFILE="${_pan_os_php_json}"
    local type_list
    type_list=$(jq -r 'keys[]' "${jsonFILE}" 2>/dev/null)

    checkArray=('in' 'out' 'actions' 'filter' 'location')

    prev2="${COMP_WORDS[COMP_CWORD-2]}"

    if [[ "${cur}" == "=" || "${prev}" == "=" ]]; then
        local RepPatt="=" RepBy=""
        local cur2="${cur//$RepPatt/$RepBy}"

        if [[ "${prev}" == "type" || "${prev2}" == "type" ]]; then
            compopt +o nospace
            COMPREPLY=($(compgen -W "${type_list}" -- "${cur2}"))

        elif [[ "${prev}" == "actions" || "${prev2}" == "actions" ]]; then
            local typeargument=""
            local KEY
            for KEY in "${!COMP_WORDS[@]}"; do
                [[ "${COMP_WORDS[$KEY]}" == "type" ]] && typeargument="${COMP_WORDS[$KEY+2]}"
            done
            local act_list
            act_list=$(jq -r ".\"${typeargument}\" | select(.action != null) | .action | keys[]" \
                       "${jsonFILE}" 2>/dev/null)
            compopt +o nospace
            COMPREPLY=($(compgen -W "${act_list}" -- "${cur2}"))

        elif [[ "${prev}" == "filter" || "${prev2}" == "filter" ]]; then
            local typeargument=""
            local KEY
            for KEY in "${!COMP_WORDS[@]}"; do
                [[ "${COMP_WORDS[$KEY]}" == "type" ]] && typeargument="${COMP_WORDS[$KEY+2]}"
            done
            local filt_list
            filt_list=$(jq -r ".\"${typeargument}\" | select(.filter != null) | .filter | keys[]" \
                        "${jsonFILE}" 2>/dev/null)
            compopt +o nospace
            COMPREPLY=($(compgen -W "${filt_list}" -- "${cur2}"))

        elif [[ "${prev}" == "vendor" || "${prev2}" == "vendor" ]]; then
            compopt +o nospace
            COMPREPLY=($(compgen -W "${vendor[*]}" -- "${cur2}"))

        elif [[ "${prev}" == "phase" || "${prev2}" == "phase" ]]; then
            compopt +o nospace
            COMPREPLY=($(compgen -W "${arguments_appidtoolbox_phase[*]}" -- "${cur2}"))

        elif [[ "${prev}" == "location" || "${prev2}" == "location" ||
                "${prev}" == "loadplugin" || "${prev2}" == "loadplugin" ||
                "${prev}" == "template" || "${prev2}" == "template" ||
                "${prev}" == "apitimeout" || "${prev2}" == "apitimeout" ]]; then
            compopt +o nospace

        elif [[ "${checkArray[*]}" =~ ${prev} || "${checkArray[*]}" =~ ${prev2} ]]; then
            local IFS=$'\n'
            compopt -o filenames
            COMPREPLY=($(compgen -f -- "${cur2}"))
        fi

    elif [[ "${cur}" == ":" || "${prev}" == ":" ]]; then
        echo ":"
    else
        # Strip already-used arguments from suggestion list
        local word prevstring=""
        for word in "${COMP_WORDS[@]}"; do
            if [[ "${word}" == "=" ]]; then
                case "${prevstring}" in
                    type*)        unset 'arguments[0]';  unset 'arguments_migration[0]'
                                  unset 'arguments_diff[0]'; unset 'arguments_appidtoolbox[0]' ;;
                    in*)          unset 'arguments[1]';  unset 'arguments_migration[1]'
                                  unset 'arguments_diff[1]'; unset 'arguments_appidtoolbox[1]' ;;
                    out*)         unset 'arguments[2]';  unset 'arguments_appidtoolbox[2]' ;;
                    actions*)     unset 'arguments[3]' ;;
                    filter*)      unset 'arguments[4]' ;;
                    location*)    unset 'arguments[5]' ;;
                    loadplugin*)  unset 'arguments[7]' ;;
                    apitimeout*)  unset 'arguments[12]' ;;
                    template*)    unset 'arguments[22]' ;;
                    vendor*)      unset 'arguments_migration[5]' ;;
                    routetable*)  unset 'arguments_migration[6]' ;;
                    mapping*)     unset 'arguments_migration[7]' ;;
                    file1*)       unset 'arguments_diff[3]' ;;
                    file2*)       unset 'arguments_diff[4]' ;;
                esac
            else
                case "${word}" in
                    loadpanoramapushedconfig) unset 'arguments[6]' ;;
                    help)                    unset 'arguments[8]';  unset 'arguments_migration[4]'
                                             unset 'arguments_diff[2]' ;;
                    listactions)             unset 'arguments[9]' ;;
                    listfilters)             unset 'arguments[10]' ;;
                    debugapi)                unset 'arguments[11]' ;;
                    shadow-apikeynohidden)   unset 'arguments[13]' ;;
                    shadow-apikeynosave)     unset 'arguments[14]' ;;
                    shadow-disableoutputformatting) unset 'arguments[15]' ;;
                    shadow-displaycurlrequest) unset 'arguments[16]' ;;
                    shadow-enablexmlduplicatesdeletion) unset 'arguments[17]' ;;
                    shadow-ignoreinvalidaddressobjects) unset 'arguments[18]' ;;
                    shadow-json)             unset 'arguments[19]' ;;
                    shadow-reducexml)        unset 'arguments[20]' ;;
                    stats)                   unset 'arguments[21]' ;;
                esac
            fi
            prevstring="${word}"
        done

        # Pick the right argument set based on type
        local typeargument="None"
        local KEY
        for KEY in "${!COMP_WORDS[@]}"; do
            [[ "${COMP_WORDS[$KEY]}" == "type" ]] && typeargument="${COMP_WORDS[$KEY+2]}"
        done

        case "${typeargument}" in
            vendor-migration) COMPREPLY=($(compgen -W "${arguments_migration[*]}" -- "${COMP_WORDS[COMP_CWORD]}")) ;;
            diff)             COMPREPLY=($(compgen -W "${arguments_diff[*]}"      -- "${COMP_WORDS[COMP_CWORD]}")) ;;
            appid-toolbox)    COMPREPLY=($(compgen -W "${arguments_appidtoolbox[*]}" -- "${COMP_WORDS[COMP_CWORD]}")) ;;
            gcp)              COMPREPLY=($(compgen -W "${arguments_gcp[*]}"       -- "${COMP_WORDS[COMP_CWORD]}")) ;;
            xpath)            COMPREPLY=($(compgen -W "${arguments_xpath[*]}"     -- "${COMP_WORDS[COMP_CWORD]}")) ;;
            *)                COMPREPLY=($(compgen -W "${arguments[*]}"           -- "${COMP_WORDS[COMP_CWORD]}")) ;;
        esac

        if [[ ${#COMPREPLY[*]} == 1 && ${COMPREPLY[0]} =~ "=" ]]; then
            compopt -o nospace
        else
            compopt +o nospace
        fi
    fi
}

    complete -o default -F __pan_os_php pan-os-php

else
    echo "pan-os-php completion: unsupported shell (need bash ≥5 or zsh)" >&2
fi
