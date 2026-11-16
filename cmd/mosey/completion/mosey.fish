# fish completion for mosey, as `mosey -completion fish` prints it.
#
#   mosey -completion fish | source
#
# or the output saved as ~/.config/fish/completions/mosey.fish.
#
# DESTINATION completes as ssh's does, with fish's own user@host helper
# (Host entries of ~/.ssh/config and what it Includes, known_hosts,
# /etc/hosts); without it, from the Host lines of ~/.ssh/config.
# localhost, this machine, is always offered. -s and -kill complete the
# sessions here, from mosey -list localhost, when DESTINATION is localhost
# or not typed yet; TAB never runs ssh. Words after DESTINATION complete
# as a command. The flags are filled in by mosey from its own flag set.

# __mosey_where: what the cursor is on, as mosey's parseArgs reads the
# words: "flag", "value FLAG DESTINATION", "ssh-value", "ssh-option",
# "destination" or "command N" (N words before the command).
function __mosey_where
    set -l all (commandline -o)
    set -l current (math (count (commandline -opc)) + 1)
    set -l -- value_flags @MOSEY_VALUE_FLAGS@
    set -l letters '@MOSEY_SSH_VALUE_LETTERS@'
    set -l n (count $all)
    test $n -lt $current; and set n $current
    set -l i 2
    set -l dest 0
    set -l dashdash 0
    set -l value_for
    set -l ssh_value 0
    while test $i -le $n
        set -l w ''
        if test $i -eq $current
            set w (commandline -ct)
        else if test $i -le (count $all)
            set w $all[$i]
        end
        set -l next (math $i + 1)
        # A lone - is DESTINATION to parseArgs and ssh, but under the
        # cursor it is the start of a flag.
        if test "$w" = '-'; and test $i -eq $current
            set w '-?'
        end
        if test $dashdash -ne 0
            if string match -qr -- '^-.' "$w"
                # ssh's getopt: the first letter taking a value ends the
                # cluster, and takes the next word if nothing follows it.
                set -l rest (string sub -s 2 -- "$w")
                while test -n "$rest"
                    set -l c (string sub -l 1 -- "$rest")
                    set rest (string sub -s 2 -- "$rest")
                    if contains -- $c (string split -- "" $letters)
                        if test -z "$rest"
                            test $next -eq $current; and set ssh_value 1
                            set next (math $i + 2)
                        end
                        break
                    end
                end
                set i $next
                continue
            end
            set dest $i
            break
        end
        switch "$w"
            case --
                set dashdash $i
            case '-*=*'
            case '-?*'
                set -l f (string replace -r -- '^--' '-' "$w")
                if contains -- $f $value_flags
                    test $next -eq $current; and set value_for $f
                    set next (math $i + 2)
                end
            case '*'
                set dest $i
                break
        end
        set i $next
    end
    set -l destination
    if test $dest -ne 0 -a $dest -ne $current
        set destination $all[$dest]
    end
    if test -n "$value_for"
        echo value $value_for $destination
    else if test $ssh_value -eq 1
        echo ssh-value
    else if test $dest -eq $current
        echo destination
    else if test $dest -ne 0 -a $current -gt $dest
        echo command $dest
    else if test $dashdash -ne 0 -a $current -gt $dashdash
        echo ssh-option
    else
        echo flag
    end
end

function __mosey_before_destination
    set -l where (string split ' ' -- (__mosey_where))
    contains -- $where[1] flag value
end

function __mosey_on
    set -l where (string split ' ' -- (__mosey_where))
    test "$where[1]" = $argv[1]
end

# __mosey_config_hosts FILE DEPTH: the Host names of ssh config FILE and
# the files it Includes, less patterns (*, ? and !).
function __mosey_config_hosts
    set -l file $argv[1]
    set -l depth $argv[2]
    test -r $file -a ! -d $file -a $depth -lt 8; or return 0
    while read -l key value
        set -l kv (string split -m 1 = -- $key)
        if test (count $kv) -eq 2
            set key $kv[1]
            set value "$kv[2] $value"
        end
        set value (string trim -l -c '= ' -- "$value")
        switch (string lower -- "$key")
            case host
                for word in (string split -n ' ' -- (string replace -a '"' '' -- $value))
                    string match -qr -- '[*?!]' $word; or echo $word
                end
            case include
                # Plain paths only: fish cannot glob a pattern held in a
                # variable without eval, and fish's own helper, which
                # this stands in for, handles Include fully.
                for word in (string split -n ' ' -- (string replace -a '"' '' -- $value))
                    string match -qr -- '[*?\[]' $word; and continue
                    switch $word
                        case '~/*'
                            set word $HOME/(string sub -s 3 -- $word)
                        case '/*'
                        case '*'
                            set word $HOME/.ssh/$word
                    end
                    __mosey_config_hosts $word (math $depth + 1)
                end
        end
    end <$file
end

function __mosey_hosts
    if functions -q __fish_complete_user_at_hosts
        __fish_complete_user_at_hosts
    else if functions -q __fish_print_hostnames
        __fish_print_hostnames
    else
        __mosey_config_hosts $HOME/.ssh/config 0
    end
    set -l token (commandline -ct)
    if string match -q -- '*@*' "$token"
        echo (string replace -r -- '@.*' '' "$token")@localhost
    else
        echo localhost
    end
end

# __mosey_sessions DESTINATION: the session names here, from the table
# mosey -list localhost prints (a header, then a name first on each line,
# or the one line "no sessions on localhost"); only for localhost or no
# DESTINATION yet, never another host.
function __mosey_sessions
    if test (count $argv) -gt 0; and test "$argv[1]" != localhost
        return 0
    end
    set -l mosey (commandline -o)[1]
    command $mosey -list localhost </dev/null 2>/dev/null | tail -n +2 | string replace -r -- '\s.*' ''
end

# __mosey_value FLAG: completes FLAG's value.
function __mosey_value
    set -l where (string split ' ' -- (__mosey_where))
    switch $argv[1]
        case s kill
            if set -q where[3]
                __mosey_sessions $where[3]
            else
                __mosey_sessions
            end
        case dir
            __fish_complete_directories (commandline -ct)
        case remote
            __fish_complete_path (commandline -ct)
        case ssh
            __fish_complete_command
        case predict
            printf '%s\n' @MOSEY_PREDICT_MODES@
        case upload
            printf '%s\n' @MOSEY_UPLOAD_MODES@
        case completion
            printf '%s\n' @MOSEY_SHELLS@
    end
end

function __mosey_command
    set -l where (string split ' ' -- (__mosey_where))
    __fish_complete_subcommand --fcs-skip=$where[2]
end

complete -c mosey -e
complete -c mosey -f
@MOSEY_FISH_FLAGS@
complete -c mosey -n '__mosey_on destination' -a '(__mosey_hosts)'
complete -c mosey -n '__mosey_on ssh-value' -F
complete -c mosey -n '__mosey_on command' -a '(__mosey_command)'
