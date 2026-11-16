#compdef mosey
# zsh completion for mosey, as `mosey -completion zsh` prints it.
#
#   source <(mosey -completion zsh)
#
# in ~/.zshrc after compinit, or the output saved as _mosey in a directory
# on $fpath.
#
# DESTINATION completes as ssh's does, by handing it to zsh's own _ssh
# (Host entries of ~/.ssh/config, known_hosts, user@host, and any ssh
# options given after --); without _ssh, from _hosts and the Host lines of
# ~/.ssh/config. localhost, this machine, is always offered. -s and -kill
# complete the sessions here, from mosey -list localhost, when DESTINATION
# is localhost or not typed yet; TAB never runs ssh. Words after
# DESTINATION complete as a command, as they would at a prompt. The flags
# are filled in by mosey from its own flag set.

# __mosey_ssh_takes_value WORD: whether ssh option WORD leaves its value to
# the next word, by ssh's getopt rules (bootstrap.SplitSSHOptions).
__mosey_ssh_takes_value() {
  local w=${1#-} c
  while [[ -n $w ]]; do
    c=${w[1]}
    w=${w[2,-1]}
    if [[ '@MOSEY_SSH_VALUE_LETTERS@' == *"$c"* ]]; then
      [[ -z $w ]]
      return
    fi
  done
  return 1
}

# __mosey_config_hosts FILE DEPTH: prints the Host names of ssh config FILE
# and the files it Includes, less patterns (*, ? and !).
__mosey_config_hosts() {
  emulate -L zsh -o extendedglob
  local file=$1 depth=$2 line key value word f
  [[ -r $file && ! -d $file ]] && (( depth < 8 )) || return 0
  while read -r line; do
    key=${line%%[[:space:]=]*}
    value=${${line#$key}##[[:space:]=]#}
    case ${(L)key} in
      host)
        for word in ${(z)value}; do
          word=${(Q)word}
          [[ -n $word && $word != *[*?!]* ]] && print -r -- $word
        done
        ;;
      include)
        for word in ${(z)value}; do
          word=${(Q)word}
          case $word in
            '~/'*) word=$HOME/${word#'~/'} ;;
            /*) ;;
            *) word=$HOME/.ssh/$word ;;
          esac
          for f in ${~word}(N); do
            __mosey_config_hosts $f $(( depth + 1 ))
          done
        done
        ;;
    esac
  done <$file
}

# __mosey_sessions DESTINATION: prints the session names here, from the
# table mosey -list localhost prints (a header, then a name first on each
# line, or the one line "no sessions on localhost"); only for localhost or
# no DESTINATION yet, never another host.
__mosey_sessions() {
  [[ -z $1 || $1 == localhost ]] || return 0
  local name rest header=1
  command ${~words[1]} -list localhost </dev/null 2>/dev/null | while read -r name rest; do
    if (( header )); then
      header=0
      continue
    fi
    print -r -- $name
  done
}

_mosey() {
  local -a flags value_flags expl
  flags=(@MOSEY_ZSH_FLAGS@ '--:ssh options follow, then DESTINATION')
  value_flags=(@MOSEY_VALUE_FLAGS@)
  local i=2 n=$#words w next dest=0 dashdash=0 value_for='' ssh_value=0
  (( n < CURRENT )) && n=$CURRENT
  # Read the words as mosey's parseArgs does, to find DESTINATION and what
  # the cursor is on: mosey's flags, each value flag taking the next word;
  # then, after --, ssh's options; DESTINATION is the first other word.
  while (( i <= n )); do
    w=$words[i]
    next=$(( i + 1 ))
    # A lone - is DESTINATION to parseArgs and ssh, but under the cursor
    # it is the start of a flag.
    [[ $w == - ]] && (( i == CURRENT )) && w='-?'
    if (( dashdash )); then
      if [[ $w == -?* ]]; then
        if __mosey_ssh_takes_value $w; then
          (( next == CURRENT )) && ssh_value=1
          next=$(( i + 2 ))
        fi
        i=$next
        continue
      fi
      dest=$i
      break
    fi
    case $w in
      --) dashdash=$i ;;
      -|[^-]*|'') dest=$i; break ;;
      -*=*) ;;
      -*)
        if (( ${value_flags[(Ie)${w/#--/-}]} )); then
          (( next == CURRENT )) && value_for=${w/#--/-}
          next=$(( i + 2 ))
        fi
        ;;
    esac
    i=$next
  done
  local destination=
  (( dest && dest != CURRENT )) && destination=$words[dest]

  if [[ -z $value_for && $PREFIX == -*=* ]] && (( !dashdash || CURRENT < dashdash )); then
    value_for=${${PREFIX%%=*}/#--/-}
    (( ${value_flags[(Ie)$value_for]} )) || return 1
    compset -P '*='
  fi

  if [[ -n $value_for ]]; then
    case $value_for in
      -s|-kill)
        local -a names
        names=(${(f)"$(__mosey_sessions $destination)"})
        _wanted sessions expl 'session' compadd -a names
        ;;
      -dir) _files -/ ;;
      -remote) _files ;;
      -ssh) _command_names -e ;;
      -predict) _wanted modes expl 'prediction' compadd @MOSEY_PREDICT_MODES@ ;;
      -upload) _wanted modes expl 'upload' compadd @MOSEY_UPLOAD_MODES@ ;;
      -completion) _wanted shells expl 'shell' compadd @MOSEY_SHELLS@ ;;
      *) _message 'value' ;;
    esac
  elif (( ssh_value )); then
    _files
  elif (( dest == CURRENT )); then
    local prefix=$PREFIX iprefix=$IPREFIX
    if (( $+functions[_ssh] )); then
      # ssh's own completion, given just what ssh would be given: its
      # options after --, and the word being typed.
      local service=ssh curcontext="${curcontext%:*:*}:ssh:"
      if (( dashdash )); then
        words=(ssh "${(@)words[dashdash+1,CURRENT]}")
      else
        words=(ssh "$words[CURRENT]")
      fi
      CURRENT=$#words
      _ssh
    else
      local -a hosts
      hosts=(${(f)"$(__mosey_config_hosts $HOME/.ssh/config 0)"})
      if compset -P '*@'; then
        _wanted hosts expl 'host' compadd -a hosts
      else
        _alternative 'hosts:host:_hosts' "config-hosts:host:compadd -a hosts"
      fi
    fi
    # Whatever the helpers did to the prefix, offer localhost against the
    # word as typed (after any user@).
    PREFIX=$prefix IPREFIX=$iprefix
    compset -P '*@'
    compadd localhost
  elif (( dest && CURRENT > dest )); then
    # The command run in place of the shell, completed as at a prompt.
    words=("${(@)words[dest+1,-1]}")
    (( CURRENT -= dest ))
    _normal
  elif (( dashdash && CURRENT > dashdash )); then
    _message 'ssh option'
  else
    _describe -t flags 'mosey flag' flags
  fi
}

if [[ $funcstack[1] == _mosey ]]; then
  # Autoloaded from $fpath as _mosey: this file is _mosey's body, so
  # complete now.
  _mosey "$@"
else
  # Sourced: register.
  compdef _mosey mosey
fi
