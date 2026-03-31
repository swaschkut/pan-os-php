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
        [[ "$w" == type=* ]] && { type_val="${w#type=}"; break; }
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

        actions=*)
            local val="${cur#actions=}"
            if [[ -n "${type_val}" ]]; then
                local -a acts
                acts=(${(f)"$(jq -r \
                    ".\"${type_val}\" | select(.action != null) | .action | keys[]" \
                    "${json_file}" 2>/dev/null)"})
                local -a suggestions
                local a
                for a in "${acts[@]}"; do
                    [[ "${a}" == ${val}* ]] && suggestions+=("actions=${a}")
                done
                compadd -S ' ' -- "${suggestions[@]}"
            fi
            ;;

        filter=*)
            local val="${cur#filter=}"
            if [[ -n "${type_val}" ]]; then
                local -a filts
                filts=(${(f)"$(jq -r \
                    ".\"${type_val}\" | select(.filter != null) | .filter | keys[]" \
                    "${json_file}" 2>/dev/null)"})
                local -a suggestions
                local f
                for f in "${filts[@]}"; do
                    [[ "${f}" == ${val}* ]] && suggestions+=("filter=${f}")
                done
                compadd -S ' ' -- "${suggestions[@]}"
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
