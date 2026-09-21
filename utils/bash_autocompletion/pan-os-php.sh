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
        ruletype= securityprofiletype= devicetype=
    help listactions listfilters version changelog stats debugapi
    loadpanoramapushedconfig
    shadow-json shadow-apikeyhidden shadow-apikeynohidden shadow-apikeynosave
    shadow-disableoutputformatting shadow-displaycurlrequest
    shadow-enablexmlduplicatesdeletion shadow-ignoreinvalidaddressobjects
    shadow-reducexml shadow-bpjsonfile shadow-displayxmlnode
    shadow-loaddghierarchy shadow-loadreduce shadow-nojson shadow-saseapiqa shadow-multivsys
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

            ruletype=*)
            local val="${cur#ruletype=}"
            local -a ruletypes
            ruletypes=(any security nat decryption appoverride captiveportal authentication pbf qos dos tunnelinspection defaultsecurity networkpacketbroker sdwan)
            local -a suggestions
            local rt
            for rt in "${ruletypes[@]}"; do
                [[ "${rt}" == ${val}* ]] && suggestions+=("ruletype=${rt}")
                done
            compadd -S ' ' -- "${suggestions[@]}"
            ;;

            securityprofiletype=*)
            local val="${cur#securityprofiletype=}"
            local -a sptypes
            sptypes=(any url-filtering virus vulnerability spyware file-blocking data-filtering wildfire-analysis custom-url-category dns-security saas-security virus-and-wildfire-analysis predefined-url predefined-url-filtering predefined-virus predefined-spyware predefined-file-blocking predefined-vulnerability predefined-wildfire-analysis)
            local -a suggestions
            local spt
            for spt in "${sptypes[@]}"; do
                [[ "${spt}" == ${val}* ]] && suggestions+=("securityprofiletype=${spt}")
                done
            compadd -S ' ' -- "${suggestions[@]}"
            ;;

            devicetype=*)
            local val="${cur#devicetype=}"
            local -a devicetypes
            devicetypes=(any vsys devicegroup templatestack template container devicecloud manageddevice deviceonprem snippet)
            local -a suggestions
            local dt
            for dt in "${devicetypes[@]}"; do
                [[ "${dt}" == ${val}* ]] && suggestions+=("devicetype=${dt}")
                done
            compadd -S ' ' -- "${suggestions[@]}"
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
            local cur prev words cword
            _get_comp_words_by_ref -n = cur prev words cword

        # Determine what string we are actually matching against based on the '=' boundary
            local real_cur="${cur}"
            if [[ "$cur" == *=* ]]; then
            real_cur="${cur#*=}"
            elif [[ "$prev" == "=" ]]; then
            real_cur="${cur}"
            fi

            declare -a arguments
            arguments=(
                'type=' 'in=' 'out=' 'actions=' 'filter=' 'location=' 'loadplugin=' 'help'
            'listactions' 'listfilters' 'debugapi' 'apitimeout='
            'shadow-apikeyhidden' 'shadow-apikeynohidden' 'shadow-apikeynosave'
            'shadow-disableoutputformatting' 'shadow-displaycurlrequest'
            'shadow-enablexmlduplicatesdeletion'
            'shadow-ignoreinvalidaddressobjects' 'shadow-json' 'shadow-reducexml'
            'shadow-bpjsonfile' 'shadow-displayxmlnode' 'shadow-loaddghierarchy'
            'shadow-loadreduce' 'shadow-nojson' 'shadow-saseapiqa' 'shadow-multivsys'
            'outputformatset='
            'stats' 'template=' 'version' 'changelog'
            'ruletype=' 'securityprofiletype=' 'devicetype='
        )

            local arguments_migration=('type=' 'in=' 'out=' 'file=' 'help' 'vendor=' 'routetable=' 'mapping=')
            local arguments_diff=('type=' 'in=' 'help' 'file1=' 'file2=')
            local arguments_appidtoolbox=('type=' 'in=' 'out=' 'help' 'phase=')
            local arguments_gcp=('type=' 'in=' 'out=' 'cluster=' 'project=' 'tenantid=' 'actions=' 'region=')
            local arguments_xpath=('type=' 'in=' 'filter-nameattribute=' 'filter-node=' 'filter-xpath='
            'filter-text=' 'display-fullxpath' 'display-nameattribute'
            'display-xmlnode' 'display-xmllineno')

            local arguments_appidtoolbox_phase=(
                    'p1-marker' 'rule-marker' 'p2-generator' 'report-generator' 'p3-cloner'
                    'rule-cloner' 'p5-activation' 'rule-activation' 'p6-cleaner' 'rule-cleaner' )

            local vendor=(ciscoasa netscreen sonicwall sophos ciscoswitch ciscoisr fortinet srx
            cp-r80 cp cp-beta huawei stonesoft sidewinder sophosxg)

            local jsonFILE="${_pan_os_php_json}"

        # ── Parse type= out of command line context ─────────────────────────────────
    local typeargument=""
            local i
            for ((i=1; i < cword; i++)); do
                if [[ "${words[i]}" == "type" && "${words[i+1]}" == "=" ]]; then
            typeargument="${words[i+2]}"
            elif [[ "${words[i]}" == type=* ]]; then
            typeargument="${words[i]#type=}"
            fi
            done

        # ── Handle value assignments after '=' ──────────────────────────────────────
    if [[ "$cur" == *=* || "$prev" == "=" ]]; then
            local assignment_target=""
            if [[ "$cur" == *=* ]]; then
            assignment_target="${cur%%=*}"
        else
            assignment_target="$prev"
            fi

        case "$assignment_target" in
            type)
            local type_list
            type_list=$(jq -r 'keys[]' "${jsonFILE}" 2>/dev/null)
            COMPREPLY=($(compgen -W "${type_list}" -- "${real_cur}"))
            return 0
                ;;
            actions)
            local act_list
            act_list=$(jq -r ".\"${typeargument}\" | select(.action != null) | .action | keys[]" "${jsonFILE}" 2>/dev/null)
            COMPREPLY=($(compgen -W "${act_list}" -- "${real_cur}"))
            return 0
                ;;
            filter)
            local filt_list
            filt_list=$(jq -r ".\"${typeargument}\" | select(.filter != null) | .filter | keys[]" "${jsonFILE}" 2>/dev/null)
            COMPREPLY=($(compgen -W "${filt_list}" -- "${real_cur}"))
            return 0
                ;;
            ruletype)
            local ruletype_list="any security nat decryption appoverride captiveportal authentication pbf qos dos tunnelinspection defaultsecurity networkpacketbroker sdwan"
            COMPREPLY=($(compgen -W "${ruletype_list}" -- "${real_cur}"))
            return 0
                ;;
            securityprofiletype)
            local securityprofiletype_list="any url-filtering virus vulnerability spyware file-blocking data-filtering wildfire-analysis custom-url-category dns-security saas-security virus-and-wildfire-analysis predefined-url predefined-url-filtering predefined-virus predefined-spyware predefined-file-blocking predefined-vulnerability predefined-wildfire-analysis"
            COMPREPLY=($(compgen -W "${securityprofiletype_list}" -- "${real_cur}"))
            return 0
                ;;
            devicetype)
            local devicetype_list="any vsys devicegroup templatestack template container devicecloud manageddevice deviceonprem snippet"
            COMPREPLY=($(compgen -W "${devicetype_list}" -- "${real_cur}"))
            return 0
                ;;
            vendor)
            COMPREPLY=($(compgen -W "${vendor[*]}" -- "${real_cur}"))
            return 0
                ;;
            phase)
            COMPREPLY=($(compgen -W "${arguments_appidtoolbox_phase[*]}" -- "${real_cur}"))
            return 0
                ;;
        in|out|location|loadplugin|file|file1|file2)
            COMPREPLY=($(compgen -f -- "${real_cur}"))
            return 0
                ;;
        *)
            return 0
                ;;
            esac
            fi

        # ── Suggest base flags if we aren't assigning values ───────────────────────
        case "${typeargument}" in
            vendor-migration) COMPREPLY=($(compgen -W "${arguments_migration[*]}" -- "${cur}")) ;;
            diff)             COMPREPLY=($(compgen -W "${arguments_diff[*]}"      -- "${cur}")) ;;
            appid-toolbox)    COMPREPLY=($(compgen -W "${arguments_appidtoolbox[*]}" -- "${cur}")) ;;
            gcp)              COMPREPLY=($(compgen -W "${arguments_gcp[*]}"       -- "${cur}")) ;;
            xpath)            COMPREPLY=($(compgen -W "${arguments_xpath[*]}"     -- "${cur}")) ;;
        *)                COMPREPLY=($(compgen -W "${arguments[*]}"           -- "${cur}")) ;;
            esac

        # Automatically handle trailing spaces depending on whether option ends in '='
            if [[ ${#COMPREPLY[*]} -eq 1 && ${COMPREPLY[0]} == *= ]]; then
            compopt -o nospace
            fi
        }

        complete -o default -F __pan_os_php pan-os-php

    else
        echo "pan-os-php completion: unsupported shell (need bash ≥5 or zsh)" >&2
        fi