#!/usr/bin/env bash
# Record keystroke/screen traces for every scenario, in parallel, inside a
# throwaway sandbox (fake HOME, fake work dir). Programs come from nixpkgs.
# Usage: record-all.sh <scratch-dir> <traces-out-dir> [rounds]
set -euo pipefail
SCR=$(realpath "$1"); OUT=$(realpath "$2"); ROUNDS=${3:-2}; ONLY=${4:-}
HERE=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$SCR/bin" "$OUT"
(cd "$HERE" && mise exec go@1.27.3 -- go build -o "$SCR/bin/" ./cmd/record ./cmd/faketui)

pkgs=(nixpkgs#zsh nixpkgs#fish nixpkgs#vim nixpkgs#less nixpkgs#bashInteractive
      nixpkgs#zsh-autosuggestions nixpkgs#zsh-syntax-highlighting nixpkgs#coreutils nixpkgs#gnugrep nixpkgs#gnumake nixpkgs#ncurses)
mapfile -t paths < <(nix build --no-link --print-out-paths "${pkgs[@]}" | grep -v -- '-man$')
P=""
for p in "${paths[@]}"; do [ -d "$p/bin" ] && P="$P:$p/bin"; done
P=${P#:}
find_pkg() { printf '%s\n' "${paths[@]}" | grep -- "$1" | head -1; }
ZAS=$(find_pkg zsh-autosuggestions)/share/zsh/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh
ZSH_HL=$(find_pkg zsh-syntax-highlighting)/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh

SB="$SCR/sandbox"; rm -rf "$SB"; mkdir -p "$SB"
mkwork() { # $1 = dir
  local w=$1; mkdir -p "$w/src" "$w/docs"
  printf '# demo\nThis is a demo project for the mosey prediction spike.\n' > "$w/README.md"
  printf 'package main\n\nfunc main() {}\n\nfunc helper() {}\n' > "$w/main.go"
  printf 'build:\n\techo building\n' > "$w/Makefile"
  for i in $(seq 1 40); do echo "note $i: the line of notes number $i for testing"; done > "$w/notes.txt"
  printf 'id,name,score\n1,ada,90\n2,bob,72\n3,cy,88\n4,di,95\n5,ed,60\n' > "$w/data.csv"
  echo 'package src' > "$w/src/alpha.go"; echo 'package src' > "$w/src/beta.go"; echo 'package src' > "$w/src/also.go"
  for i in $(seq 1 600); do
    case $((i % 37)) in 0) echo "$i error: something failed here";; 5) echo "$i warning: be careful";; *) echo "$i ordinary log line with some text in it";; esac
  done > "$w/big.txt"
}
HIST=("ls -la" "cat README.md" "grep -n func main.go" "echo hello world" "head -n 5 data.csv" "wc -l notes.txt" "make build" "grep -n main main.go")

common_env=(env -i "PATH=$P" "TERM=xterm-256color" "LANG=C.UTF-8" "LC_ALL=C.UTF-8" "COLUMNS=80" "LINES=24")

run() { # name, home, workdir, extra env..., -- cmd...
  local name=$1 home=$2 work=$3; shift 3
  if [ -n "$ONLY" ] && [ "$ONLY" != "$name" ]; then return 0; fi
  local envs=()
  while [ "$1" != "--" ]; do envs+=("$1"); shift; done; shift
  (cd "$work" && "${common_env[@]}" "HOME=$home" "${envs[@]}" "$SCR/bin/record" -scenario "$name" -rounds "$ROUNDS" -seed "$SEED" -out "$OUT/$name.json.gz" -- "$@") \
    > "$OUT/$name.log" 2>&1 &
}

SEED=11
# bash
H="$SB/bash"; mkdir -p "$H"; mkwork "$H/work"
printf '%s\n' "${HIST[@]}" > "$H/.bash_history"
cat > "$H/.bashrc" <<'EOF'
PS1='\[\e[34m\]\w\[\e[0m\] \$ '
HISTFILE=~/.bash_history
EOF
run bash "$H" "$H/work" -- bash --noprofile --rcfile "$H/.bashrc" -i

# zsh plain
SEED=12
H="$SB/zsh-plain"; mkdir -p "$H"; mkwork "$H/work"
printf '%s\n' "${HIST[@]}" > "$H/.zsh_history"
cat > "$H/.zshrc" <<EOF
HISTFILE=\$ZDOTDIR/.zsh_history; HISTSIZE=1000; SAVEHIST=1000
autoload -Uz compinit && compinit -u -d \$ZDOTDIR/.zcompdump
PROMPT='%F{blue}%~%f %# '
EOF
run zsh-plain "$H" "$H/work" "ZDOTDIR=$H" -- zsh -i

# zsh "modern": autosuggestions + syntax highlighting + right prompt + transient prompt
SEED=13
H="$SB/zsh-full"; mkdir -p "$H"; mkwork "$H/work"
printf '%s\n' "${HIST[@]}" > "$H/.zsh_history"
cat > "$H/.zshrc" <<EOF
HISTFILE=\$ZDOTDIR/.zsh_history; HISTSIZE=1000; SAVEHIST=1000
autoload -Uz compinit && compinit -u -d \$ZDOTDIR/.zcompdump
setopt PROMPT_SUBST
PROMPT='%F{blue}%~%f %F{green}❯%f '
RPROMPT='%F{8}%n@sandbox %*%f'
source $ZAS
source $ZSH_HL
# transient prompt: redraw the finished line with a short prompt and no RPROMPT
zle-line-init() {
  emulate -L zsh
  [[ \$CONTEXT == start ]] || return 0
  while true; do
    zle .recursive-edit
    local -i ret=\$?
    [[ \$ret == 0 && \$KEYS == \$'\\4' ]] || break
    [[ -o ignore_eof ]] || exit 0
  done
  local sp=\$PROMPT sr=\$RPROMPT
  PROMPT='%F{green}❯%f '; RPROMPT=''
  zle .reset-prompt
  PROMPT=\$sp; RPROMPT=\$sr
  if (( ret )); then zle .send-break; else zle .accept-line; fi
  return ret
}
zle -N zle-line-init
EOF
run zsh-full "$H" "$H/work" "ZDOTDIR=$H" -- zsh -i

# fish (defaults: autosuggestions, highlighting, pager) + right prompt + transient prompt
SEED=14
H="$SB/fish"; mkdir -p "$H/.config/fish" "$H/.local/share/fish"; mkwork "$H/work"
for c in "${HIST[@]}"; do printf -- '- cmd: %s\n  when: 1700000000\n' "$c"; done > "$H/.local/share/fish/fish_history"
cat > "$H/.config/fish/config.fish" <<'EOF'
set -g fish_greeting ''
function fish_right_prompt; set_color brblack; date +%H:%M:%S; set_color normal; end
set -g fish_transient_prompt 1
function fish_prompt
  if contains -- --final-rendering $argv
    set_color green; echo -n '❯ '; set_color normal
  else
    set_color blue; echo -n (prompt_pwd)' '; set_color green; echo -n '❯ '; set_color normal
  end
end
EOF
run fish "$H" "$H/work" "XDG_CONFIG_HOME=$H/.config" "XDG_DATA_HOME=$H/.local/share" -- fish -i

# vim
SEED=15
H="$SB/vim"; mkdir -p "$H"; mkwork "$H/work"
cat > "$H/.vimrc" <<'EOF'
set nocompatible
syntax on
set ruler showmode noswapfile viminfo= backspace=indent,eol,start
EOF
run vim "$H" "$H/work" -- vim -u "$H/.vimrc" -i NONE notes.txt

# less
SEED=16
H="$SB/less"; mkdir -p "$H"; mkwork "$H/work"
run less "$H" "$H/work" "LESSHISTFILE=-" -- less big.txt

# Ink-like TUI (Claude Code stand-in), both cursor styles
SEED=17
H="$SB/tui"; mkdir -p "$H"; mkwork "$H/work"
run tui-fakecursor "$H" "$H/work" -- "$SCR/bin/faketui" -cursor=fake
SEED=18
run tui-realcursor "$H" "$H/work" -- "$SCR/bin/faketui" -cursor=real

wait
for f in "$OUT"/*.log; do head -1 "$f"; done
