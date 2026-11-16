# shellcheck shell=bash
# bash completion for mosey, as `mosey -completion bash` prints it.
#
#   source <(mosey -completion bash)
#
# in ~/.bashrc, or the output saved as
# ~/.local/share/bash-completion/completions/mosey.
#
# DESTINATION completes as ssh's does, with bash-completion's own
# known-hosts helper when it is loaded: Host entries of ~/.ssh/config and
# the files it Includes, known_hosts, user@host. Without bash-completion it
# falls back to the Host lines of ~/.ssh/config (and its Includes), less
# patterns. localhost, this machine, is always offered. -s and -kill
# complete the sessions here, from mosey -list localhost, when DESTINATION
# is localhost or not typed yet; TAB never runs ssh. Words after
# DESTINATION complete as a command, as they would at a prompt.
#
# Works in bash 3.2 (macOS's) as well as bash 5 (D22): no mapfile, no
# associative arrays, no ${x,,}. The flags and their values are filled in
# by mosey from its own flag set, so they cannot drift from it.

_mosey_flags='@MOSEY_FLAGS@'
_mosey_value_flags=' @MOSEY_VALUE_FLAGS@ '
_mosey_ssh_value_letters='@MOSEY_SSH_VALUE_LETTERS@'

# _mosey_add CUR: adds each line of stdin that starts with CUR to
# COMPREPLY. Matching by hand rather than with compgen -W, which would
# expand $(...) in a hostname read from a file.
_mosey_add() {
    local line
    while IFS= read -r line; do
        [[ $line && $line == "$1"* ]] && COMPREPLY+=("$line")
    done
}

# _mosey_takes_value WORD: whether WORD is one of mosey's flags that takes
# a value. The flag package accepts --flag as -flag.
_mosey_takes_value() {
    local w=$1
    [[ $w == --?* ]] && w=${w#-}
    [[ $_mosey_value_flags == *" $w "* ]]
}

# _mosey_ssh_takes_value WORD: whether ssh option WORD leaves its value to
# the next word, by ssh's getopt rules (bootstrap.SplitSSHOptions): the
# first letter that takes a value ends the cluster, and takes the rest of
# it or, if there is none, the next word.
_mosey_ssh_takes_value() {
    local w=${1#-} c
    while [[ $w ]]; do
        c=${w:0:1}
        w=${w:1}
        if [[ $_mosey_ssh_value_letters == *"$c"* ]]; then
            [[ -z $w ]]
            return
        fi
    done
    return 1
}

# _mosey_config_hosts FILE DEPTH: prints the Host names of ssh config FILE
# and the files it Includes, less patterns (*, ? and !), which name no host.
_mosey_config_hosts() {
    local file=$1 depth=$2 key value word f
    local -a words
    [[ -r $file && ! -d $file ]] && ((depth < 8)) || return 0
    while read -r key value; do
        # Keyword=value, and Keyword = value, are ssh's other spellings.
        if [[ $key == *=* ]]; then
            value="${key#*=} $value"
            key=${key%%=*}
        fi
        value=${value#=}
        # read -a splits without the pathname expansion a bare $value
        # would do on Host *.
        read -r -a words <<<"$value"
        case $key in
        [Hh][Oo][Ss][Tt])
            for word in "${words[@]}"; do
                word=${word//\"/}
                case $word in
                '' | *[*?!]*) ;;
                *) printf '%s\n' "$word" ;;
                esac
            done
            ;;
        [Ii][Nn][Cc][Ll][Uu][Dd][Ee])
            for word in "${words[@]}"; do
                word=${word//\"/}
                case $word in
                \~/*) word=$HOME/${word#\~/} ;;
                /*) ;;
                *) word=$HOME/.ssh/$word ;;
                esac
                while IFS= read -r f; do
                    _mosey_config_hosts "$f" $((depth + 1))
                done < <(compgen -G "$word")
            done
            ;;
        esac
    done <"$file"
}

# _mosey_hosts CUR: sets COMPREPLY to the hosts ssh CUR<TAB> would offer,
# and localhost.
_mosey_hosts() {
    local cur=$1 user='' host h
    COMPREPLY=()
    if declare -F _comp_compgen_known_hosts >/dev/null; then
        _comp_compgen_known_hosts -a -- "$cur"
    elif declare -F _known_hosts_real >/dev/null; then
        _known_hosts_real -a -- "$cur"
    else
        [[ $cur == *@* ]] && user=${cur%%@*}@
        _mosey_add "${cur#*@}" < <(_mosey_config_hosts "$HOME/.ssh/config" 0 | sort -u)
        if ((${#COMPREPLY[@]})); then
            COMPREPLY=("${COMPREPLY[@]/#/$user}")
        fi
    fi
    host=${cur#*@}
    [[ $cur == *@* ]] && user=${cur%%@*}@
    if [[ localhost == "$host"* ]]; then
        for h in "${COMPREPLY[@]}"; do
            [[ $h == "${user}localhost" ]] && return 0
        done
        COMPREPLY+=("${user}localhost")
    fi
    return 0
}

# _mosey_sessions DESTINATION: prints the session names here, from the
# table mosey -list localhost prints (a header line, then a session's name
# first on each line, or the one line "no sessions on localhost"). Only for
# localhost, or no DESTINATION yet: never another host, which would mean
# running ssh on a TAB.
_mosey_sessions() {
    [[ -z $1 || $1 == localhost ]] || return 0
    local mosey=${COMP_WORDS[0]} name rest header=1
    [[ $mosey == \~/* ]] && mosey=$HOME/${mosey#\~/}
    while read -r name rest; do
        if ((header)); then
            header=0
            continue
        fi
        printf '%s\n' "$name"
    done < <(command "$mosey" -list localhost </dev/null 2>/dev/null)
}

# _mosey_value FLAG CUR DESTINATION: completes FLAG's value.
_mosey_value() {
    local flag=${1#-} cur=$2 prefix=''
    flag=${flag#-}
    # With the cursor just after -flag=, bash's word is "=": complete
    # "=VALUE" in its place.
    if [[ $cur == =* ]]; then
        prefix='='
        cur=${cur#=}
    fi
    case $flag in
    s | kill) _mosey_add "$cur" < <(_mosey_sessions "$3") ;;
    predict) _mosey_add "$cur" < <(printf '%s\n' @MOSEY_PREDICT_MODES@) ;;
    upload) _mosey_add "$cur" < <(printf '%s\n' @MOSEY_UPLOAD_MODES@) ;;
    completion) _mosey_add "$cur" < <(printf '%s\n' @MOSEY_SHELLS@) ;;
    dir)
        compopt -o filenames 2>/dev/null
        _mosey_add "$cur" < <(compgen -d -- "$cur")
        ;;
    remote)
        compopt -o filenames 2>/dev/null
        _mosey_add "$cur" < <(compgen -f -- "$cur")
        ;;
    ssh)
        compopt -o filenames 2>/dev/null
        if [[ $cur == */* ]]; then
            _mosey_add "$cur" < <(compgen -f -- "$cur")
        else
            _mosey_add "$cur" < <(compgen -c -- "$cur" | sort -u)
        fi
        ;;
    esac
    if [[ $prefix ]] && ((${#COMPREPLY[@]})); then
        COMPREPLY=("${COMPREPLY[@]/#/$prefix}")
    fi
    return 0
}

_mosey() {
    local cur=${COMP_WORDS[COMP_CWORD]} i=1 n=${#COMP_WORDS[@]} w next
    local dest=0 dashdash=0 value_for='' ssh_value=0
    COMPREPLY=()
    # Read the words as parseArgs does, to find DESTINATION and what the
    # cursor is on: mosey's flags, each value flag taking the next word
    # (or, as bash splits -flag=value, the "=" and the word after it); then,
    # after --, ssh's options; DESTINATION is the first other word.
    while ((i < n)); do
        w=${COMP_WORDS[i]}
        next=$((i + 1))
        # A lone - is DESTINATION to parseArgs and ssh, but under the
        # cursor it is the start of a flag.
        [[ $w == - ]] && ((i == COMP_CWORD)) && w='-?'
        if ((dashdash)); then
            if [[ $w == -?* ]]; then
                if _mosey_ssh_takes_value "$w"; then
                    ((next == COMP_CWORD)) && ssh_value=1
                    next=$((i + 2))
                fi
                i=$next
                continue
            fi
            dest=$i
            break
        fi
        case $w in
        --) dashdash=$i ;;
        - | [!-]* | '') dest=$i && break ;;
        -*=*) ;;
        -*)
            if [[ ${COMP_WORDS[next]-} == = ]]; then
                # -flag=value as bash splits it: -flag, =, value.
                if ((next == COMP_CWORD)); then
                    value_for=$w
                elif ((next + 1 == COMP_CWORD)) && _mosey_takes_value "$w"; then
                    value_for=$w
                fi
                next=$((next + 2))
            elif _mosey_takes_value "$w"; then
                ((next == COMP_CWORD)) && value_for=$w
                next=$((next + 1))
            fi
            ;;
        esac
        i=$next
    done
    local destination=''
    ((dest)) && destination=${COMP_WORDS[dest]}
    ((dest == COMP_CWORD)) && destination=''

    if [[ $value_for ]]; then
        _mosey_value "$value_for" "$cur" "$destination"
    elif [[ $cur == -*=* ]] && ((!dashdash || COMP_CWORD < dashdash)); then
        # -flag=value in one word (bash-completion's own word splitting).
        w=${cur%%=*}
        _mosey_takes_value "$w" && _mosey_value "$w" "=${cur#*=}" "$destination"
        if ((${#COMPREPLY[@]})); then
            COMPREPLY=("${COMPREPLY[@]/#/$w}")
        fi
    elif ((ssh_value)); then
        # -F, -i and -E name files; the rest take whatever ssh takes.
        compopt -o filenames 2>/dev/null
        _mosey_add "$cur" < <(compgen -f -- "$cur")
    elif ((dest == COMP_CWORD)); then
        _mosey_hosts "$cur"
    elif ((dest && COMP_CWORD > dest)); then
        # The command run in place of the shell: complete it as at a
        # prompt, as sudo's completion does.
        if declare -F _comp_command_offset >/dev/null; then
            _comp_command_offset $((dest + 1))
        elif declare -F _command_offset >/dev/null; then
            _command_offset $((dest + 1))
        elif ((COMP_CWORD == dest + 1)); then
            _mosey_add "$cur" < <(compgen -c -- "$cur" | sort -u)
        else
            compopt -o filenames 2>/dev/null
            _mosey_add "$cur" < <(compgen -f -- "$cur")
        fi
    elif ((dashdash && COMP_CWORD > dashdash)); then
        : # an ssh option: ssh's own business
    else
        # shellcheck disable=SC2086 # the flags are words, split on purpose
        _mosey_add "$cur" < <(printf '%s\n' $_mosey_flags --)
    fi
    return 0
}

complete -F _mosey mosey
