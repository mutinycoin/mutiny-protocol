#!/usr/bin/env perl
# build/check-source-paths.pl - Linux (POSIX) source-path portability check for Mutiny Build 8.
#
# Why. Every Build 8 run so far was on Windows, whose path handling hides failures that stop a Linux build:
# (a) rustc joins a #[path] written inside an inline `mod name { .. }` block to a directory named after the
# inline module(s), which need not exist; Windows collapses `..` lexically before it touches the file system,
# Linux walks every component and fails with ENOENT; (b) Windows (and macOS) match names case-insensitively,
# Linux does not; (c) a CRLF shell script fails on Linux ($'\r': command not found); (d) names that differ only
# by case cannot both exist in a case-insensitive checkout. This script applies the POSIX rules on ANY host.
#
# Usage: perl build/check-source-paths.pl [--root DIR] [--verbose] [--no-git] [--selftest]
#   Exit 0 when there is no failing finding, 1 when there is one, 2 on a usage error.
#   One line per finding, `path:line: message` (repository-relative, `/` separators), sorted; the last line is
#   a summary. Findings in the Windows-only desktop crate, or in code under a cfg that is false on x86_64 Linux,
#   print as `path:line: windows-only: message` and do not fail. --verbose adds `info:` lines (every
#   concat!(env!("CARGO_MANIFEST_DIR"), ..) include, checked against its crate root; arguments that cannot be
#   resolved statically; the directory each source lock resolves under). --selftest builds scratch trees under
#   $TMPDIR, checks that every finding class is reported and that a clean tree passes (it never reads or writes
#   the repository). Perl 5.14 or later; no module beyond Cwd (Ubuntu's minimal perl-base is enough).
#
# The tree. In a git work tree (a .git entry at the root, git on PATH, no --no-git) the tree is the git INDEX
# (`git ls-files`): exactly what a clone or `git archive` (the Linux package) contains, so an untracked file or
# a stray local directory cannot satisfy a reference. Otherwise (an extracted package) it is the file system,
# listed with readdir (exact names); .git, target/ and the vendored dependency cache vendor/ are not scanned for
# names, scripts or C includes.
#
# Resolution, as the Linux kernel does it: component by component from the root; every component must be an
# entry of its directory with EXACT case (a case-insensitive host cannot hide a mismatch); `..` only steps out
# of a directory that exists (never lexical collapsing); a reference may not leave the root; every component but
# the last must be a directory.
#
# Checks. Rust sources are every file reachable from a target of the root crates (consensus, node, crypto-v2,
# transport-v2, wallet-core, release-signer: failing; desktop: windows-only) and from the library and build
# script of every path dependency and [patch] they name.
#  1 #[path] (and cfg_attr(.., path = ..)) on `mod` items, from rustc's base directory (below).
#  2 include!, include_str!, include_bytes!: from the directory of the FILE that holds the call;
#    concat!(env!("CARGO_MANIFEST_DIR"), "/..") from the crate root. A file included with include! is walked as
#    a module source (rustc resolves its `mod` items from its own directory).
#  3 `mod name;`: exactly one of name.rs and name/mod.rs, exact case, from the module directory.
#  4 Cargo.toml: `path` of every dependency, dev-, build- and target-dependency (a directory holding Cargo.toml),
#    [patch] and [replace]; [lib], [[bin]], [[test]], [[example]] and [[bench]] paths and inferred explicit
#    targets of the root crates; package.build; the [workspace] root that inherited keys come from and its members.
#  5 a backslash (or an absolute path) in a path literal of 1, 2 or 4: `\` separates on Windows and is an
#    ordinary file-name character on Linux.
#  6 shell scripts (*.sh, *.bash, *.pl anywhere; any file starting with #! under build/ and package/): no
#    carriage return anywhere, `#!` at the first byte (a byte-order mark breaks it).
#  7 names in the tree: two names in one directory that differ only by case, a component ending in a dot or a
#    space, a Windows-reserved name (CON, PRN, AUX, NUL, COM1-9, LPT1-9, with any extension), a character
#    Windows forbids (<>:"|?*\ and control characters).
#  8 build scripts (build.rs of every crate walked, run from the crate root): a literal starting with ./ or ../
#    must resolve; any other path-like literal (a fragment joined to another base) must match a tracked path
#    suffix exactly when it matches one ignoring case; every JSON source lock a build script names must list
#    files that all exist, with exact case and without a backslash, under ONE directory (`files`, and
#    `sources.<name>.files` for each <name> the build script spells as a literal).
#  9 C and C++ sources and headers: an #include that matches a tracked path only ignoring case, or that holds a
#    backslash.
#
# Rust module paths (rustc_expand/src/module.rs; each case was confirmed with rustc 1.98.1 on synthetic crates
# on Windows, where the cases differ in which existing file is used):
#  * A module file has a directory D (the directory of the file) and, when it was loaded by default as name.rs
#    (a "non-mod-rs" file), a stem `name`. Crate roots, mod.rs files, files loaded through #[path] (even x.rs)
#    and files loaded through include! have no stem.
#  * `#[path = P] mod x;` outside inline modules: D/P (the stem is NOT added).
#  * `mod x;` outside inline modules: D/stem/x.rs or D/stem/x/mod.rs (D/x.rs, D/x/mod.rs without a stem).
#  * Inside inline `mod a { mod b { .. } }` the base is D/stem/a/b (the stem, if any, then one directory per
#    enclosing inline module), for #[path] and for plain `mod`. Those directories usually do not exist: Windows
#    resolves D\a\b\..\..\x lexically, Linux needs D/a and D/a/b on disk.
#  * An inline module that carries #[path = P] itself names the directory B/P, B being its parent's base
#    WITHOUT the stem; modules inside it continue from there.
#  * In a file loaded through include!, `mod` items resolve from the included file's directory, without a
#    stem; the inline modules around the include! call do not apply.
#
# Limits (a static model, not a Linux build):
#  * The lexer handles line and nested block comments, string, byte and C strings with escapes, raw strings
#    with any number of #, char and byte literals (including '{', '"' and '\''), lifetimes, labels and raw
#    identifiers. It does not expand macros: `mod` items and #[path] produced by macro_rules! expansions and
#    include arguments built from macro variables are not resolved (the latter is an info line). A literal
#    include path inside a macro_rules! body is resolved from the defining file (a cross-file invocation
#    resolves from the caller's file).
#  * cfg handling is coarse: a `mod` item, or a braced or ';'-terminated item, under a cfg that is false on
#    x86_64 Linux (windows, another target_os, ...) is classified windows-only; any other cfg (test, features,
#    unknown) is assumed compiled. An attributed item without braces ends at the next ';' or ',' at its depth
#    (generic arguments such as A<B, C> end it early, which can only make a finding stricter).
#  * Paths computed at run time (Path::new(env!("CARGO_MANIFEST_DIR")).join(..), std::fs reads, process
#    arguments) and build-script logic beyond literals are not resolved; JSON source locks are read line by line
#    and must be pretty-printed one key per line. Symbolic links are not modelled (the tree has none).
#  * It cannot see linker, system-library, kernel, permission, timing, locale or environment differences, or
#    anything else that only a Linux build and test run can show.
use strict;
use warnings;
use Cwd ();

my $ME = 'check-source-paths';
my @FAIL_ROOTS = qw(consensus node crypto-v2 transport-v2 wallet-core release-signer);
my @WIN_ROOTS  = qw(desktop);

my %OPT = (root => undef, verbose => 0, nogit => 0, selftest => 0);
sub usage {
  my ($why) = @_;
  print STDERR "$ME: $why\n" if defined $why;
  print STDERR "usage: perl build/check-source-paths.pl [--root DIR] [--verbose] [--no-git] [--selftest]\n";
  exit 2;
}
sub main {
  while (@ARGV) {
    my $arg = shift @ARGV;
    if    ($arg eq '--root')                  { defined($OPT{root} = shift @ARGV) or usage('--root needs a directory'); }
    elsif ($arg =~ /^--root=(.+)$/)           { $OPT{root} = $1; }
    elsif ($arg eq '--verbose' || $arg eq '-v') { $OPT{verbose} = 1; }
    elsif ($arg eq '--no-git')                { $OPT{nogit} = 1; }
    elsif ($arg eq '--selftest')              { $OPT{selftest} = 1; }
    elsif ($arg eq '--help' || $arg eq '-h')  { usage(); }
    else                                      { usage("unknown argument '$arg'"); }
  }
  return selftest() if $OPT{selftest};
  my $root = $OPT{root};
  if (!defined $root) { ($root = $0) =~ s{[^/\\]*$}{}; $root = ($root eq '' ? '.' : $root) . '/..'; }
  my $abs = Cwd::abs_path($root);
  usage("not a directory: $root") unless defined $abs && -d $abs;
  my $S = run_checks($abs, { nogit => $OPT{nogit}, fail_roots => \@FAIL_ROOTS, win_roots => \@WIN_ROOTS });
  print_report($S, $OPT{verbose});
  return count_sev($S, 'fail') ? 1 : 0;
}

# ======================================================================================== the run
sub run_checks {
  my ($root, $o) = @_;
  $root =~ s{\\}{/}g;
  $root =~ s{/+$}{} unless $root eq '/';
  my $S = { root => $root, mode => 'fs', dirs => {}, disk => {}, F => {}, events => {}, visited => {},
            manifests => {}, crate_done => {}, build_scripts => {}, roots => [],
            st => { rust => {}, refs => 0, deps => {}, scripts => 0 } };
  if (!$o->{nogit} && -e "$root/.git") {
    my @files = git_ls_files($root);
    if (@files) {
      $S->{mode} = 'git';
      $S->{dirs}{''} = {};
      add_tree_path($S, $_) for @files;
      $S->{all} = [ sort @files ];
    }
  }
  $S->{all} = [ fs_walk($S) ] if $S->{mode} eq 'fs';
  for my $c (@{$o->{fail_roots}}) { do_root($S, $c, 'fail') if tree_type($S, "$c/Cargo.toml") eq 'f'; }
  for my $c (@{$o->{win_roots}})  { do_root($S, $c, 'windows') if tree_type($S, "$c/Cargo.toml") eq 'f'; }
  check_build_scripts($S);
  check_scripts($S);
  finding($S, 'fail', $_->[0], 1, $_->[1]) for @{ name_findings($S->{all}) };
  check_c_includes($S);
  # Rust sources that no target reaches are not compiled, so nothing above checked them (--verbose lists them:
  # a module the walk failed to follow would show up here).
  for my $f (grep { /\.rs$/ && !$S->{st}{rust}{$_} } @{$S->{all}}) {
    info($S, $f, 1, "Rust source not reached from any crate target or path dependency: not compiled, not checked");
  }
  return $S;
}

# ======================================================================================== findings
my %RANK = (info => 0, win => 1, fail => 2);
sub finding {
  my ($S, $sev, $file, $line, $msg) = @_;
  my $k = "$file\0$line\0$msg";
  my $old = $S->{F}{$k};
  if (!$old) { $S->{F}{$k} = { file => $file, line => $line, msg => $msg, sev => $sev }; }
  elsif ($RANK{$sev} > $RANK{$old->{sev}}) { $old->{sev} = $sev; }
}
sub info { my ($S, $file, $line, $msg) = @_; finding($S, 'info', $file, $line, $msg); }
sub findings_sorted {
  my ($S) = @_;
  return sort { $a->{file} cmp $b->{file} || $a->{line} <=> $b->{line} || $a->{msg} cmp $b->{msg} } values %{$S->{F}};
}
sub count_sev { my ($S, $sev) = @_; return scalar grep { $_->{sev} eq $sev } values %{$S->{F}}; }
sub print_report {
  my ($S, $verbose) = @_;
  for my $x (findings_sorted($S)) {
    next if $x->{sev} eq 'info' && !$verbose;
    my $tag = $x->{sev} eq 'win' ? 'windows-only: ' : $x->{sev} eq 'info' ? 'info: ' : '';
    print "$x->{file}:$x->{line}: $tag$x->{msg}\n";
  }
  printf "%s: %d failing finding(s), %d windows-only (not failing); %s mode (%s); roots: %s; %d path dependencies; %d Rust sources walked; %d path references resolved; %d shell/perl scripts; %d names\n",
    $ME, count_sev($S, 'fail'), count_sev($S, 'win'), $S->{mode},
    ($S->{mode} eq 'git' ? 'the git index is the tree' : 'the file system is the tree'),
    join(' ', @{$S->{roots}}) || 'none', scalar(keys %{$S->{st}{deps}}), scalar(keys %{$S->{st}{rust}}),
    $S->{st}{refs}, $S->{st}{scripts}, scalar(@{$S->{all}});
}

# ======================================================================================== the tree
sub git_ls_files {
  my ($root) = @_;
  my $fh;
  open($fh, '-|', 'git', '-C', $root, 'ls-files', '-z') or return ();
  local $/;
  my $out = <$fh>;
  close $fh or return ();
  return () unless defined $out;
  return grep { length } split /\0/, $out;
}
sub add_tree_path {
  my ($S, $p) = @_;
  my @c = split m{/}, $p;
  my $d = '';
  for my $i (0 .. $#c) {
    my $t = $i == $#c ? 'f' : 'd';
    $S->{dirs}{$d}{$c[$i]} = $t unless ($S->{dirs}{$d}{$c[$i]} // '') eq 'd';
    $d = $d eq '' ? $c[$i] : "$d/$c[$i]";
    $S->{dirs}{$d} ||= {} if $t eq 'd';
  }
}
sub disk_list {   # exact entry names of a directory on disk (undef when it is not a directory)
  my ($S, $d) = @_;
  return $S->{disk}{$d} if exists $S->{disk}{$d};
  my $abs = $d eq '' ? $S->{root} : "$S->{root}/$d";
  my $dh;
  return $S->{disk}{$d} = undef unless opendir($dh, $abs);
  my %e;
  for my $n (readdir $dh) { next if $n eq '.' || $n eq '..'; $e{$n} = -d "$abs/$n" ? 'd' : 'f'; }
  closedir $dh;
  return $S->{disk}{$d} = \%e;
}
sub tree_list {   # the entries of a tree directory: name => 'd' | 'f'
  my ($S, $d) = @_;
  return $S->{dirs}{$d} if exists $S->{dirs}{$d};
  return undef if $S->{mode} eq 'git';
  return $S->{dirs}{$d} = disk_list($S, $d);
}
sub fs_walk {
  my ($S) = @_;
  my (@out, @queue);
  @queue = ('');
  while (@queue) {
    my $d = shift @queue;
    my $l = tree_list($S, $d) or next;
    for my $n (sort keys %$l) {
      my $p = $d eq '' ? $n : "$d/$n";
      if ($l->{$n} eq 'd') {
        next if $n eq '.git' || $n eq 'target' || ($d eq '' && $n eq 'vendor');
        push @queue, $p;
      } elsif (!($d eq '' && $n eq '.git')) { push @out, $p; }
    }
  }
  return sort @out;
}
sub parent_comps { my @c = split m{/}, $_[0]; pop @c; return @c; }
sub read_text {
  my ($S, $rel) = @_;
  my $fh;
  open($fh, '<:raw', "$S->{root}/$rel") or return undef;
  local $/;
  my $t = <$fh>;
  close $fh;
  return defined $t ? $t : '';
}

# Resolve the components of BASE (may hold '.' and '..') followed by P, from the root, with POSIX semantics.
# { ok => 1, rel, type => 'f'|'d' } or { ok => 0, why => missing|case|notdir|escape, at, idx, actual, dir, name }.
sub resolve {
  my ($S, $base, $p) = @_;
  my @comps = (@$base, split(m{/}, $p, -1));
  my $last = -1;
  for my $i (0 .. $#comps) { $last = $i if $comps[$i] ne '' && $comps[$i] ne '.'; }
  my (@cur, $type);
  $type = 'd';
  for my $i (0 .. $#comps) {
    my $c = $comps[$i];
    next if $c eq '' || $c eq '.';
    if ($c eq '..') {
      return { ok => 0, why => 'escape', at => join('/', @cur, '..'), idx => $i } unless @cur;
      pop @cur; $type = 'd'; next;
    }
    my $dir = join '/', @cur;
    my $l = tree_list($S, $dir) || {};
    my $t = $l->{$c};
    if (!defined $t) {
      my ($ci) = sort grep { lc($_) eq lc($c) } keys %$l;
      return { ok => 0, why => (defined $ci ? 'case' : 'missing'), at => ($dir eq '' ? $c : "$dir/$c"),
               actual => (defined $ci ? ($dir eq '' ? $ci : "$dir/$ci") : undef), idx => $i, dir => $dir, name => $c };
    }
    push @cur, $c;
    $type = $t;
    return { ok => 0, why => 'notdir', at => join('/', @cur), idx => $i } if $t eq 'f' && $i != $last;
  }
  return { ok => 0, why => 'notdir', at => join('/', @cur), idx => $#comps } if $type eq 'f' && $p =~ m{/$};
  return { ok => 1, rel => join('/', @cur), type => $type };
}
sub tree_type { my ($S, $p) = @_; my $r = resolve($S, [], $p); return $r->{ok} ? $r->{type} : ''; }
sub why_text {
  my ($S, $r) = @_;
  my $w = $r->{why};
  return "'..' leaves the repository root" if $w eq 'escape';
  return "'$r->{at}' is a file, not a directory" if $w eq 'notdir';
  return "'$r->{at}' is a directory, not a file" if $w eq 'isdir';
  return "'$r->{at}' does not exist: the directory holds '$r->{actual}' (the case differs; Linux is case-sensitive, Windows matches either)" if $w eq 'case';
  my $t = "'$r->{at}' does not exist";
  if ($S->{mode} eq 'git' && defined $r->{dir}) {
    my $dl = disk_list($S, $r->{dir});
    $t .= " in the git index (it is in the working tree but untracked: a clone and the Linux package do not contain it)"
      if $dl && exists $dl->{$r->{name}};
  }
  return $t;
}
sub bad_literal {
  my ($p) = @_;
  return "empty path" if $p eq '';
  return "backslash in a path literal ('\\' separates on Windows and is an ordinary file-name character on Linux; use '/')" if $p =~ /\\/;
  return "absolute path (not portable)" if $p =~ m{^/} || $p =~ /^[A-Za-z]:/;
  return undef;
}

# ======================================================================================== Rust lexer
# Tokens as parallel arrays: T type ('i' identifier, 's' string literal with its decoded value, 'p' one of the
# punctuation characters # ! [ ] ( ) { } ; , = $), V value, L line. Comments, char literals, lifetimes, numbers
# and all other punctuation are dropped.
sub lex_rust {
  my ($s) = @_;
  my (@T, @V, @L);
  my $line = 1;
  my $len = length $s;
  pos($s) = 0;
  $s =~ /\G\xEF\xBB\xBF/gc;
  $s =~ /\G#!(?![ \t]*\[)[^\n]*/gc;
  while (pos($s) < $len) {
    last unless $s =~ m~\G(?:
        ([ \t\r\f\x0b]+)
      | (\n)
      | (//[^\n]*)
      | (/\*)
      | [bc]?r(\#*)"
      | [bc]?"((?:[^"\\]++|\\.)*+)"
      | (b?'(?:[\xc0-\xff][\x80-\xbf]+|\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,8}\}|[^\n])|[^\\'\n])')
      | ('(?:r\#)?[A-Za-z_][A-Za-z0-9_]*)
      | (?:r\#)?([A-Za-z_][A-Za-z0-9_]*)
      | ([0-9][0-9A-Za-z_]*)
      | ([\#!\[\](){};,=\$])
      | ([\x80-\xff]+|.)
    )~gcsx;
    if    (defined $9)  { push @T, 'i'; push @V, $9; push @L, $line; }
    elsif (defined $11) { push @T, 'p'; push @V, $11; push @L, $line; }
    elsif (defined $2)  { $line++; }
    elsif (defined $6)  { my $raw = $6; push @T, 's'; push @V, unescape_rust($raw); push @L, $line; $line += ($raw =~ tr/\n//); }
    elsif (defined $5)  {
      my $close = '"' . $5;
      my $start = pos($s);
      my $end = index($s, $close, $start);
      $end = $len if $end < 0;
      my $val = substr($s, $start, $end - $start);
      push @T, 's'; push @V, $val; push @L, $line;
      $line += ($val =~ tr/\n//);
      pos($s) = $end + length($close) > $len ? $len : $end + length($close);
    }
    elsif (defined $4)  {
      my $depth = 1;
      while ($depth > 0 && pos($s) < $len) {
        if    ($s =~ m{\G[^/*\n]+}gc) { }
        elsif ($s =~ m{\G\n}gc)       { $line++; }
        elsif ($s =~ m{\G/\*}gc)      { $depth++; }
        elsif ($s =~ m{\G\*/}gc)      { $depth--; }
        else                          { $s =~ m{\G.}gcs; }
      }
    }
  }
  my $X = { T => \@T, V => \@V, L => \@L };
  match_brackets($X);
  return $X;
}
sub u8chr { my $c = chr($_[0]); utf8::encode($c); return $c; }
sub unescape_rust {
  my ($s) = @_;
  return $s if index($s, '\\') < 0;
  $s =~ s!\\(?:(\r?\n)[ \t\r\n]*|x([0-9a-fA-F]{2})|u\{([0-9a-fA-F_]{1,8})\}|(.))!
          defined $1 ? '' : defined $2 ? chr(hex $2) : defined $3 ? u8chr(hex($3 =~ tr/_//dr)) :
          $4 eq 'n' ? "\n" : $4 eq 't' ? "\t" : $4 eq 'r' ? "\r" : $4 eq '0' ? "\0" : $4!gse;
  return $s;
}
sub match_brackets {   # M: index of the matching bracket for every bracket (unbalanced openers run to the end)
  my ($X) = @_;
  my ($T, $V) = ($X->{T}, $X->{V});
  my (@M, @st);
  for my $i (0 .. $#$T) {
    next unless $T->[$i] eq 'p';
    my $v = $V->[$i];
    if    ($v eq '(' || $v eq '[' || $v eq '{') { push @st, $i; }
    elsif ($v eq ')' || $v eq ']' || $v eq '}') { if (@st) { my $o = pop @st; $M[$o] = $i; $M[$i] = $o; } else { $M[$i] = $i; } }
  }
  $M[$_] = scalar(@$T) for @st;
  $X->{M} = \@M;
}

# ======================================================================================== Rust parser
# cfg predicates on x86_64 Linux (gnu or musl): 1 true, 0 false, undef unknown (test, features, ...).
my %CFG_FLAG = (unix => 1, windows => 0);
my %CFG_KV = (target_os => { linux => 1 }, target_family => { unix => 1 }, target_arch => { x86_64 => 1 },
              target_pointer_width => { 64 => 1 }, target_endian => { little => 1 },
              target_vendor => { unknown => 1 }, target_env => { gnu => undef, musl => undef });
sub cfg_pred {   # ($X, $i, $end) -> (value, index after the predicate)
  my ($X, $i, $end) = @_;
  my ($T, $V, $M) = @$X{qw(T V M)};
  return (undef, $end) if $i >= $end;
  return (undef, $i + 1) if $T->[$i] ne 'i';
  my $name = $V->[$i];
  if ($i + 1 < $end && $T->[$i + 1] eq 'p' && $V->[$i + 1] eq '(') {
    my $close = $M->[$i + 1];
    my (@vals, $k);
    $k = $i + 2;
    while ($k < $close) {
      my ($v, $nx) = cfg_pred($X, $k, $close);
      push @vals, $v;
      $k = $nx > $k ? $nx : $k + 1;
      $k++ if $k < $close && $T->[$k] eq 'p' && $V->[$k] eq ',';
    }
    my $val;
    if ($name eq 'not') { $val = (@vals == 1 && defined $vals[0]) ? 1 - $vals[0] : undef; }
    elsif ($name eq 'all') { $val = 1; for my $x (@vals) { if (defined $x && !$x) { $val = 0; last; } $val = undef unless defined $x; } }
    elsif ($name eq 'any') { $val = 0; for my $x (@vals) { if (defined $x && $x) { $val = 1; last; } $val = undef unless defined $x; } }
    return ($val, $close + 1);
  }
  if ($i + 2 < $end && $T->[$i + 1] eq 'p' && $V->[$i + 1] eq '=' && $T->[$i + 2] eq 's') {
    my $tab = $CFG_KV{$name};
    return (undef, $i + 3) unless $tab;
    return ((exists $tab->{$V->[$i + 2]} ? $tab->{$V->[$i + 2]} : 0), $i + 3);
  }
  return ((exists $CFG_FLAG{$name} ? $CFG_FLAG{$name} : undef), $i + 1);
}
sub parse_attr {   # the tokens strictly between '[' and ']': { path, line, nl }
  my ($X, $a, $b) = @_;
  my ($T, $V, $L, $M) = @$X{qw(T V L M)};
  my %at = (nl => 0);
  return \%at if $a >= $b || $T->[$a] ne 'i';
  my $name = $V->[$a];
  if ($name eq 'path' && $a + 2 < $b && $T->[$a + 1] eq 'p' && $V->[$a + 1] eq '=' && $T->[$a + 2] eq 's') {
    @at{qw(path line)} = ($V->[$a + 2], $L->[$a + 2]);
  } elsif ($name eq 'cfg' && $a + 1 < $b && $T->[$a + 1] eq 'p' && $V->[$a + 1] eq '(') {
    my ($v) = cfg_pred($X, $a + 2, $M->[$a + 1]);
    $at{nl} = 1 if defined $v && !$v;
  } elsif ($name eq 'cfg_attr' && $a + 1 < $b && $T->[$a + 1] eq 'p' && $V->[$a + 1] eq '(') {
    my $close = $M->[$a + 1];
    my ($v, $k) = cfg_pred($X, $a + 2, $close);
    while ($k < $close) {
      if ($T->[$k] eq 'i' && $V->[$k] eq 'path' && $k + 2 < $close && $T->[$k + 1] eq 'p' && $V->[$k + 1] eq '=' && $T->[$k + 2] eq 's') {
        # applies on Linux unless the predicate is false there (then the default module path applies)
        if (!defined $v || $v) { $at{path} //= $V->[$k + 2]; $at{line} //= $L->[$k + 2]; }
        $k += 3; next;
      }
      $k = ($T->[$k] eq 'p' && $V->[$k] =~ /^[(\[{]$/) ? $M->[$k] + 1 : $k + 1;
    }
  }
  return \%at;
}
sub is_mod_item {
  my ($X, $k) = @_;
  my ($T, $V) = @$X{qw(T V)};
  return $k + 2 < @$T && $T->[$k] eq 'i' && $V->[$k] eq 'mod' && $T->[$k + 1] eq 'i' && $T->[$k + 2] eq 'p'
      && ($V->[$k + 2] eq ';' || $V->[$k + 2] eq '{');
}
sub include_event {   # ($X, name index, opening delimiter index)
  my ($X, $i, $o) = @_;
  my ($T, $V, $L, $M) = @$X{qw(T V L M)};
  my $c = $M->[$o];
  my %e = (t => 'inc', mac => $V->[$i], line => $L->[$i], kind => 'other');
  my $j = $o + 1;
  if ($j < $c && $T->[$j] eq 's' && ($j + 1 == $c || ($j + 2 == $c && $T->[$j + 1] eq 'p' && $V->[$j + 1] eq ','))) {
    @e{qw(kind value line)} = ('lit', $V->[$j], $L->[$j]);
    return \%e;
  }
  if ($j + 2 < $c && $T->[$j] eq 'i' && $V->[$j] eq 'concat' && $T->[$j + 1] eq 'p' && $V->[$j + 1] eq '!'
      && $T->[$j + 2] eq 'p' && $V->[$j + 2] =~ /^[(\[{]$/) {
    my $cc = $M->[$j + 2];
    my (@pieces, $first);
    my $k = $j + 3;
    while ($k < $cc) {
      if ($T->[$k] eq 's') { push @pieces, ['lit', $V->[$k]]; $first //= $L->[$k]; $k++; }
      elsif ($T->[$k] eq 'i' && $V->[$k] eq 'env' && $k + 3 < $cc && $T->[$k + 1] eq 'p' && $V->[$k + 1] eq '!'
             && $T->[$k + 2] eq 'p' && $T->[$k + 3] eq 's') {
        push @pieces, ['env', $V->[$k + 3]]; $k = $M->[$k + 2] + 1;
      } else {
        push @pieces, ['other', $V->[$k]];
        $k = ($T->[$k] eq 'p' && $V->[$k] =~ /^[(\[{]$/) ? $M->[$k] + 1 : $k + 1;
        $k++ while $k < $cc && !($T->[$k] eq 'p' && $V->[$k] eq ',');
      }
      $k++ if $k < $cc && $T->[$k] eq 'p' && $V->[$k] eq ',';
    }
    $e{line} = $first if defined $first;
    my @kinds = map { $_->[0] } @pieces;
    if (@pieces && !grep { $_ ne 'lit' } @kinds) {
      @e{qw(kind value)} = ('lit', join('', map { $_->[1] } @pieces));
    } elsif (@pieces >= 2 && $kinds[0] eq 'env' && $pieces[0][1] eq 'CARGO_MANIFEST_DIR' && !grep { $_ ne 'lit' } @kinds[1 .. $#kinds]) {
      @e{qw(kind value)} = ('manifest', join('', map { $_->[1] } @pieces[1 .. $#pieces]));
    } elsif (grep { $_->[0] eq 'env' && $_->[1] eq 'OUT_DIR' } @pieces) {
      $e{kind} = 'outdir';
    }
  }
  return \%e;
}
# Events of one Rust file, independent of how the file is reached: out-of-line `mod` items (with the enclosing
# inline modules and their #[path]) and include macro calls. `nl`: under a cfg that is false on x86_64 Linux.
sub parse_events {
  my ($X) = @_;
  my ($T, $V, $L, $M) = @$X{qw(T V L M)};
  my $n = @$T;
  my (@ev, @stack, @pending, %modattrs, $item);
  my $file_nl = 0;
  my $nl_now = sub {
    return 1 if $file_nl || ($item && $item->{nl});
    for my $f (@stack) { return 1 if $f->{nl}; }
    return 0;
  };
  my $in_macro = sub { for my $f (@stack) { return 1 if $f->{kind} eq 'macro'; } return 0; };
  my $i = 0;
  while ($i < $n) {
    my ($t, $v) = ($T->[$i], $V->[$i]);
    if ($t eq 'p' && $v eq '#') {
      my $j = $i + 1;
      my $inner = 0;
      if ($j < $n && $T->[$j] eq 'p' && $V->[$j] eq '!') { $inner = 1; $j++; }
      if ($j < $n && $T->[$j] eq 'p' && $V->[$j] eq '[') {
        my $end = $M->[$j];
        my $attr = parse_attr($X, $j + 1, $end);
        for (my $k = $j + 1; $k < $end; $k++) {   # include macros inside the attribute (#[doc = include_str!(..)])
          next unless $T->[$k] eq 'i' && $V->[$k] =~ /^include(?:_str|_bytes)?$/ && $k + 2 < $end
                   && $T->[$k + 1] eq 'p' && $V->[$k + 1] eq '!' && $T->[$k + 2] eq 'p' && $V->[$k + 2] =~ /^[(\[{]$/;
          my $e = include_event($X, $k, $k + 2);
          @$e{qw(nl in_macro)} = ($nl_now->(), $in_macro->());
          push @ev, $e;
          $k = $M->[$k + 2];
        }
        if ($inner) { $file_nl = 1 if !@stack && $attr->{nl}; }
        else        { push @pending, $attr; }
        $i = $end + 1;
        next;
      }
    }
    if (@pending) {   # the first token of the attributed item
      my $k = $i;
      if ($k < $n && $T->[$k] eq 'i' && $V->[$k] eq 'pub') {
        $k++;
        $k = $M->[$k] + 1 if $k < $n && $T->[$k] eq 'p' && $V->[$k] eq '(';
      }
      $k++ if $k < $n && $T->[$k] eq 'i' && $V->[$k] eq 'unsafe';
      if (is_mod_item($X, $k)) { $modattrs{$k} = [ @pending ]; }
      elsif (grep { $_->{nl} } @pending) { $item = { depth => scalar(@stack), nl => 1 }; }
      @pending = ();
    }
    if ($t eq 'i') {
      if ($v eq 'mod' && is_mod_item($X, $i)) {
        my $attrs = $modattrs{$i} || [];
        my ($pa) = grep { defined $_->{path} } @$attrs;
        my $own_nl = (grep { $_->{nl} } @$attrs) ? 1 : 0;
        my @mods = map { { name => $_->{name}, path => $_->{path} } } grep { $_->{kind} eq 'mod' } @stack;
        if ($V->[$i + 2] eq ';') {
          push @ev, { t => 'mod', name => $V->[$i + 1], line => $L->[$i], mods => \@mods,
                      nl => ($own_nl || $nl_now->()) ? 1 : 0, in_macro => $in_macro->(),
                      (defined $pa ? (path => $pa->{path}, pline => $pa->{line}) : ()) };
        } else {
          push @stack, { kind => 'mod', name => $V->[$i + 1], path => (defined $pa ? $pa->{path} : undef), nl => $own_nl };
        }
        $i += 3;
        next;
      }
      if ($v eq 'macro_rules' && $i + 3 < $n && $T->[$i + 1] eq 'p' && $V->[$i + 1] eq '!' && $T->[$i + 2] eq 'i'
          && $T->[$i + 3] eq 'p' && $V->[$i + 3] =~ /^[(\[{]$/) {
        push @stack, { kind => 'macro', nl => 0 };
        $i += 4;
        next;
      }
      if (($v eq 'include' || $v eq 'include_str' || $v eq 'include_bytes') && $i + 2 < $n && $T->[$i + 1] eq 'p'
          && $V->[$i + 1] eq '!' && $T->[$i + 2] eq 'p' && $V->[$i + 2] =~ /^[(\[{]$/) {
        my $e = include_event($X, $i, $i + 2);
        @$e{qw(nl in_macro)} = ($nl_now->(), $in_macro->());
        push @ev, $e;
        $i = $M->[$i + 2] + 1;
        next;
      }
    } elsif ($t eq 'p') {
      if ($v eq '{' || $v eq '(' || $v eq '[') {
        my $fnl = 0;
        if ($item && $v eq '{' && $item->{depth} == @stack) { $fnl = 1; $item->{opened} = 1; }
        push @stack, { kind => 'other', nl => $fnl };
      } elsif ($v eq '}' || $v eq ')' || $v eq ']') {
        pop @stack if @stack;
        $item = undef if $item && (@stack < $item->{depth} || ($item->{opened} && @stack == $item->{depth}));
      } elsif (($v eq ';' || $v eq ',') && $item && @stack == $item->{depth}) {
        $item = undef;
      }
    }
    $i++;
  }
  return \@ev;
}
sub events_for {
  my ($S, $file) = @_;
  return $S->{events}{$file} if exists $S->{events}{$file};
  my $text = read_text($S, $file);
  return $S->{events}{$file} = undef unless defined $text;
  return $S->{events}{$file} = parse_events(lex_rust($text));
}

# ======================================================================================== module walk
sub sev_of { my ($ctx, $nl) = @_; return ($ctx->{crate}{sev} eq 'windows' || $nl) ? 'win' : 'fail'; }
sub child_ctx {
  my ($ctx, $rel, $stem, $nl) = @_;
  return { dir => [ parent_comps($rel) ], rel => $stem, crate => $ctx->{crate}, nl => $nl ? 1 : 0 };
}
sub walk_file {
  my ($S, $file, $ctx) = @_;
  my $key = join "\0", $file, join('/', @{$ctx->{dir}}), $ctx->{rel} // '', $ctx->{crate}{dir}, $ctx->{crate}{sev}, $ctx->{nl};
  return if $S->{visited}{$key}++;
  $S->{st}{rust}{$file} = 1;
  my $ev = events_for($S, $file);
  if (!$ev) { finding($S, sev_of($ctx, $ctx->{nl}), $file, 1, "cannot read this module source"); return; }
  for my $e (@$ev) {
    my $nl = ($ctx->{nl} || $e->{nl}) ? 1 : 0;
    if ($e->{t} eq 'mod') { mod_event($S, $file, $ctx, $e, $nl); }
    else                  { inc_event($S, $file, $ctx, $e, $nl); }
  }
}
sub inline_text {
  my ($names) = @_;
  return '' unless @$names;
  return ' inside inline module ' . join('::', map { "`$_`" } @$names);
}
sub mod_event {
  my ($S, $file, $ctx, $e, $nl) = @_;
  my $sv = sev_of($ctx, $nl);
  if ($e->{in_macro}) {
    info($S, $file, $e->{line}, "mod $e->{name}; inside a macro_rules! body resolves at each expansion site: not checked");
    return;
  }
  # rustc's module directory: the file's directory; inside inline modules the stem (if any) and one directory
  # per inline module; an inline module with its own #[path] names a directory relative to its parent's base.
  my @dir = @{$ctx->{dir}};
  my $nreal = @dir;
  my $stem = $ctx->{rel};
  my @names;
  for my $m (@{$e->{mods}}) {
    push @names, $m->{name};
    if (defined $m->{path}) {
      if (my $bad = bad_literal($m->{path})) {
        finding($S, $sv, $file, $e->{line}, "#[path = \"$m->{path}\"] on inline module `$m->{name}`: $bad");
        return;
      }
      push @dir, split(m{/}, $m->{path});
      $stem = undef;
    } else {
      push @dir, $stem if defined $stem;
      $stem = undef;
      push @dir, $m->{name};
    }
  }
  $S->{st}{refs}++;
  my $derived = (@names || defined $stem) ? 1 : 0;
  if (defined $e->{path}) {
    my $p = $e->{path};
    my $line = $e->{pline} // $e->{line};
    my $what = "#[path = \"$p\"]" . inline_text(\@names);
    if (my $bad = bad_literal($p)) { finding($S, $sv, $file, $line, "$what: $bad"); return; }
    my $r = resolve($S, \@dir, $p);
    if ($r->{ok} && $r->{type} eq 'f') { walk_file($S, $r->{rel}, child_ctx($ctx, $r->{rel}, undef, $nl)); return; }
    $r = { ok => 0, why => 'isdir', at => $r->{rel}, idx => -1 } if $r->{ok};
    my $from = join('/', @dir) . '/';
    if (@names && $r->{why} ne 'isdir' && $r->{idx} >= $nreal && $r->{idx} < @dir) {
      finding($S, $sv, $file, $line, "$what resolves from $from (rustc adds the file stem, if any, and one directory per "
        . "enclosing inline module); " . why_text($S, $r) . ", so Linux cannot resolve the path through it (ENOENT); "
        . "Windows collapses '..' lexically and hides this. Declare the module at file scope (or in the crate root) instead");
    } else {
      finding($S, $sv, $file, $line, "$what: " . why_text($S, $r) . " (resolved from $from)");
    }
    return;
  }
  push @dir, $stem if defined $stem;
  my $from = @dir ? join('/', @dir) . '/' : '';
  my $a = resolve($S, \@dir, "$e->{name}.rs");
  my $b = resolve($S, \@dir, "$e->{name}/mod.rs");
  my $ao = $a->{ok} && $a->{type} eq 'f';
  my $bo = $b->{ok} && $b->{type} eq 'f';
  my $what = "mod $e->{name};" . inline_text(\@names);
  if ($ao && $bo) { finding($S, $sv, $file, $e->{line}, "$what: both $a->{rel} and $b->{rel} exist (rustc rejects the ambiguity)"); return; }
  if ($ao) { walk_file($S, $a->{rel}, child_ctx($ctx, $a->{rel}, $e->{name}, $nl)); return; }
  if ($bo) { walk_file($S, $b->{rel}, child_ctx($ctx, $b->{rel}, undef, $nl)); return; }
  my $why;
  if    (!$a->{ok} && $a->{why} eq 'case' && $a->{idx} >= @dir) { $why = why_text($S, $a); }
  elsif (!$b->{ok} && $b->{why} eq 'case' && $b->{idx} >= @dir) { $why = why_text($S, $b); }
  elsif (!$a->{ok} && $a->{idx} < @dir) { $why = "the module directory: " . why_text($S, $a); }
  else  { $why = "neither ${from}$e->{name}.rs nor ${from}$e->{name}/mod.rs exists" . ($derived ? " (module directory $from)" : ''); }
  finding($S, $sv, $file, $e->{line}, "$what: $why");
}
sub inc_event {
  my ($S, $file, $ctx, $e, $nl) = @_;
  my $sv = sev_of($ctx, $nl);
  my $mac = "$e->{mac}!";
  if ($e->{kind} eq 'other') {
    info($S, $file, $e->{line}, "$mac argument is neither a string literal nor concat!(env!(\"CARGO_MANIFEST_DIR\"), ..): not checked");
    return;
  }
  if ($e->{kind} eq 'outdir') { info($S, $file, $e->{line}, "$mac from OUT_DIR (generated at build time): not checked"); return; }
  $S->{st}{refs}++;
  my ($p, $base, $shown) = ($e->{value});
  if ($e->{kind} eq 'lit') {
    $base = [ parent_comps($file) ];
    $shown = "$mac(\"$p\")";
  } else {
    $shown = "$mac(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"$p\"))";
    info($S, $file, $e->{line}, "$shown is checked against the crate root $ctx->{crate}{dir}/");
    if (substr($p, 0, 1) ne '/') { finding($S, $sv, $file, $e->{line}, "$shown: the literal after CARGO_MANIFEST_DIR must start with '/'"); return; }
    $p = substr($p, 1);
    $base = [ split m{/}, $ctx->{crate}{dir} ];
  }
  if (my $bad = bad_literal($p)) { finding($S, $sv, $file, $e->{line}, "$shown: $bad"); return; }
  my $r = resolve($S, $base, $p);
  if ($r->{ok} && $r->{type} eq 'f') {
    walk_file($S, $r->{rel}, child_ctx($ctx, $r->{rel}, undef, $nl)) if $e->{mac} eq 'include';
    return;
  }
  $r = { ok => 0, why => 'isdir', at => $r->{rel} } if $r->{ok};
  finding($S, $sv, $file, $e->{line}, "$shown: " . why_text($S, $r)
    . ($e->{in_macro} ? ' (inside a macro_rules! body: resolved from the defining file)' : ''));
}

# ======================================================================================== Cargo manifests
sub toml_string {   # a basic "..." or literal '...' TOML string at the start of $v, else undef
  my ($v) = @_;
  if ($v =~ /^"((?:[^"\\]|\\.)*)"/) { my $s = $1; $s =~ s/\\(["\\])/$1/g; return $s; }
  return $1 if $v =~ /^'([^']*)'/;
  return undef;
}
sub toml_inline {   # the string value of key $k inside an inline table
  my ($v, $k) = @_;
  return toml_string($1) if $v =~ /(?:^|[{,\s])\Q$k\E\s*=\s*(".*|'.*)$/;
  return undef;
}
sub parse_manifest {
  my ($text) = @_;
  my %m = (deps => [], targets => [], auto => { bin => 1, test => 1, example => 1, bench => 1 }, inherits => 0, members => []);
  my ($table, $entry, $ml) = ('', undef, undef);
  my $ln = 0;
  for my $raw (split /\n/, $text) {
    $ln++;
    (my $l = $raw) =~ s/\r$//;
    if ($ml) {
      $ml->[2] .= " $l";
      if ($l =~ /\]/) { push @{$m{members}}, map { [$_, $ml->[1]] } ($ml->[2] =~ /"([^"]*)"/g) if $ml->[3]; $ml = undef; }
      next;
    }
    $l =~ s/^\s+//;
    next if $l eq '' || $l =~ /^#/;
    if ($l =~ /^\[\[\s*([^\]]+?)\s*\]\]/) {
      $table = $1;
      $entry = { kind => $table, line => $ln };
      push @{$m{targets}}, $entry if $table =~ /^(?:bin|test|example|bench)$/;
      next;
    }
    if ($l =~ /^\[(.+)\]\s*(?:#.*)?$/) { ($table = $1) =~ s/[\s"']//g; $entry = undef; next; }
    next unless $l =~ /^("[^"]*"|'[^']*'|[A-Za-z0-9_.\-]+)\s*=\s*(.*)$/;
    my ($key, $val) = ($1, $2);
    $key =~ s/^["']//; $key =~ s/["']$//;
    my $ws = ($table eq 'workspace' && ($key eq 'members' || $key eq 'exclude')) ? 1 : 0;
    if ($val =~ /^\[/ && $val !~ /\]/) { $ml = [$key, $ln, $val, $ws && $key eq 'members']; next; }
    $m{inherits} = 1 if ($key =~ /\.workspace$/ && $val =~ /^true\b/) || $val =~ /\bworkspace\s*=\s*true\b/;
    my $str = toml_string($val);
    if ($table =~ /(?:^|\.)(?:dev-|build-)?dependencies$/ || $table =~ /^patch\.[^.]+$/ || $table eq 'replace') {
      my $kind = $table =~ /^patch\./ ? 'patch' : $table eq 'replace' ? 'replace' : $table =~ /dev-dependencies$/ ? 'dev' : 'dep';
      my ($dep, $path) = ($key, undef);
      if ($val =~ /^\{/) { $path = toml_inline($val, 'path'); }
      elsif ($key =~ /^(.+)\.path$/) { ($dep, $path) = ($1, $str); }
      push @{$m{deps}}, { name => $dep, path => $path, line => $ln, kind => $kind, table => $table } if defined $path;
      next;
    }
    if ($table =~ /^(?:(?:target\..+\.)?(?:dev-|build-)?dependencies|patch\.[^.]+)\.([^.]+)$/) {
      my $dep = $1;
      push @{$m{deps}}, { name => $dep, path => $str, line => $ln, table => $table,
                          kind => ($table =~ /^patch\./ ? 'patch' : $table =~ /dev-dependencies\./ ? 'dev' : 'dep') }
        if $key eq 'path' && defined $str;
      next;
    }
    if ($table eq 'package') {
      if    ($key eq 'name')      { $m{name} = $str; }
      elsif ($key eq 'build')     { $m{build} = defined $str ? $str : ($val =~ /^false\b/ ? 'false' : undef); $m{build_line} = $ln; }
      elsif ($key eq 'workspace') { $m{ws_path} = $str; $m{ws_line} = $ln; }
      elsif ($key =~ /^auto(bins|tests|examples|benches)$/) {
        my %k = (bins => 'bin', tests => 'test', examples => 'example', benches => 'bench');
        my $kind = $k{$1};
        $m{auto}{$kind} = $val =~ /^false\b/ ? 0 : 1;
      }
      next;
    }
    if ($table eq 'lib') { @m{qw(lib_path lib_line)} = ($str, $ln) if $key eq 'path'; next; }
    if ($entry && $table =~ /^(?:bin|test|example|bench)$/) {
      if    ($key eq 'name') { $entry->{name} = $str; }
      elsif ($key eq 'path') { @$entry{qw(path pline)} = ($str, $ln); }
      next;
    }
    if ($ws && $key eq 'members') { push @{$m{members}}, map { [$_, $ln] } ($val =~ /"([^"]*)"/g); next; }
    $m{workspace} = 1 if $table eq 'workspace';
  }
  $m{workspace} = 1 if $text =~ /^\[workspace\]/m;
  return \%m;
}
sub read_manifest {
  my ($S, $dir) = @_;
  return $S->{manifests}{$dir} if exists $S->{manifests}{$dir};
  my $file = $dir eq '' ? 'Cargo.toml' : "$dir/Cargo.toml";
  my $text = read_text($S, $file);
  my $m = defined $text ? parse_manifest($text) : undef;
  @$m{qw(dir file)} = ($dir, $file) if $m;
  return $S->{manifests}{$dir} = $m;
}
sub do_root {
  my ($S, $dir, $sev) = @_;
  my $m = read_manifest($S, $dir) or return;
  push @{$S->{roots}}, $dir;
  process_crate($S, $m, { dir => $dir, sev => $sev }, 1);
}
sub manifest_path {   # a file path from a manifest: the relative path, or undef after a finding
  my ($S, $m, $sv, $p, $line, $what) = @_;
  if (my $bad = bad_literal($p)) { finding($S, $sv, $m->{file}, $line, "$what = \"$p\": $bad"); return undef; }
  my $r = resolve($S, [ split m{/}, $m->{dir} ], $p);
  return $r->{rel} if $r->{ok} && $r->{type} eq 'f';
  $r = { ok => 0, why => 'isdir', at => $r->{rel} } if $r->{ok};
  finding($S, $sv, $m->{file}, $line, "$what = \"$p\": " . why_text($S, $r));
  return undef;
}
sub listing_files {   # (dir) -> sorted names of files directly in a tree directory
  my ($S, $d) = @_;
  my $l = tree_list($S, $d) or return ();
  return sort grep { $l->{$_} eq 'f' } keys %$l;
}
sub listing_dirs {
  my ($S, $d) = @_;
  my $l = tree_list($S, $d) or return ();
  return sort grep { $l->{$_} eq 'd' } keys %$l;
}
sub process_crate {
  my ($S, $m, $crate, $is_root) = @_;
  return if $S->{crate_done}{ join "\0", $m->{dir}, $crate->{sev}, $is_root }++;
  my $sv = $crate->{sev} eq 'windows' ? 'win' : 'fail';
  my $pre = $m->{dir} eq '' ? '' : "$m->{dir}/";
  my @files;
  if (defined $m->{lib_path}) { push @files, manifest_path($S, $m, $sv, $m->{lib_path}, $m->{lib_line}, '[lib] path'); }
  elsif (tree_type($S, "${pre}src/lib.rs") eq 'f') { push @files, "${pre}src/lib.rs"; }
  my $bs;
  if (defined $m->{build}) { $bs = manifest_path($S, $m, $sv, $m->{build}, $m->{build_line}, 'package.build') unless $m->{build} eq 'false'; }
  elsif (tree_type($S, "${pre}build.rs") eq 'f') { $bs = "${pre}build.rs"; }
  if (defined $bs) {
    push @files, $bs;
    my $old = $S->{build_scripts}{$bs};
    $S->{build_scripts}{$bs} = [ $m->{dir}, $sv ] if !$old || $RANK{$sv} > $RANK{$old->[1]};
  }
  if ($is_root) {
    my %auto = (bin => "${pre}src/bin", test => "${pre}tests", example => "${pre}examples", bench => "${pre}benches");
    push @files, "${pre}src/main.rs" if $m->{auto}{bin} && tree_type($S, "${pre}src/main.rs") eq 'f';
    for my $k (qw(bin test example bench)) {
      next unless $m->{auto}{$k};
      push @files, map { "$auto{$k}/$_" } grep { /\.rs$/ } listing_files($S, $auto{$k});
      push @files, map { "$auto{$k}/$_/main.rs" } grep { tree_type($S, "$auto{$k}/$_/main.rs") eq 'f' } listing_dirs($S, $auto{$k});
    }
    for my $t (@{$m->{targets}}) {
      if (defined $t->{path}) { push @files, manifest_path($S, $m, $sv, $t->{path}, $t->{pline}, "[[$t->{kind}]] path"); next; }
      next unless defined $t->{name};
      my @cand = ("$auto{$t->{kind}}/$t->{name}.rs", "$auto{$t->{kind}}/$t->{name}/main.rs");
      push @cand, "${pre}src/main.rs" if $t->{kind} eq 'bin' && defined $m->{name} && $t->{name} eq $m->{name};
      my ($hit) = grep { tree_type($S, $_) eq 'f' } @cand;
      if (defined $hit) { push @files, $hit; }
      else { finding($S, $sv, $m->{file}, $t->{line}, "[[$t->{kind}]] name = \"$t->{name}\": no target file; Cargo looks for " . join(' or ', @cand) . " with exact case"); }
    }
  }
  for my $d (@{$m->{deps}}) {
    next if !$is_root && ($d->{kind} eq 'dev' || $d->{kind} eq 'patch' || $d->{kind} eq 'replace');
    my $what = "path = \"$d->{path}\" ($d->{kind} '$d->{name}' in [$d->{table}])";
    if (my $bad = bad_literal($d->{path})) { finding($S, $sv, $m->{file}, $d->{line}, "$what: $bad"); next; }
    my $r = resolve($S, [ split m{/}, $m->{dir} ], $d->{path});
    if (!$r->{ok}) { finding($S, $sv, $m->{file}, $d->{line}, "$what: " . why_text($S, $r)); next; }
    if ($r->{type} ne 'd') { finding($S, $sv, $m->{file}, $d->{line}, "$what: '$r->{rel}' is not a directory"); next; }
    if (tree_type($S, ($r->{rel} eq '' ? '' : "$r->{rel}/") . 'Cargo.toml') ne 'f') {
      my $l = tree_list($S, $r->{rel}) || {};
      my ($ci) = grep { lc($_) eq 'cargo.toml' } keys %$l;
      finding($S, $sv, $m->{file}, $d->{line}, "$what: $r->{rel}/ has no Cargo.toml" . (defined $ci ? " (it has '$ci'; Cargo needs the exact name on Linux)" : ''));
      next;
    }
    next if $r->{rel} eq $m->{dir};
    my $dm = read_manifest($S, $r->{rel}) or next;
    $S->{st}{deps}{$r->{rel}} = 1;
    process_crate($S, $dm, { dir => $r->{rel}, sev => $crate->{sev} }, 0);
  }
  check_workspace_root($S, $m, $sv) if $m->{inherits};
  walk_file($S, $_, { dir => [ parent_comps($_) ], rel => undef, crate => { dir => $m->{dir}, sev => $crate->{sev} }, nl => 0 })
    for grep { defined } @files;
}
sub check_workspace_root {   # inherited keys need an ancestor manifest with [workspace]; its members must exist
  my ($S, $m, $sv) = @_;
  my @c = split m{/}, $m->{dir};
  my $found;
  if (defined $m->{ws_path}) {
    my $r = resolve($S, [ @c ], $m->{ws_path});
    $found = $r->{rel} if $r->{ok} && $r->{type} eq 'd';
  } else {
    while (1) {
      my $d = join '/', @c;
      my $wm = tree_type($S, ($d eq '' ? '' : "$d/") . 'Cargo.toml') eq 'f' ? read_manifest($S, $d) : undef;
      if ($wm && $wm->{workspace}) { $found = $d; last; }
      last unless @c;
      pop @c;
    }
  }
  if (!defined $found) { finding($S, $sv, $m->{file}, 1, "inherits workspace keys but no ancestor directory holds a Cargo.toml with [workspace] (exact name)"); return; }
  my $wm = read_manifest($S, $found) or return;
  return if $S->{ws_done}{$found}++;
  for my $mem (@{$wm->{members}}) {
    my ($p, $line) = @$mem;
    next if $p =~ /[*?\[]/;
    my $r = resolve($S, [ split m{/}, $found ], "$p/Cargo.toml");
    finding($S, $sv, $wm->{file}, $line, "workspace member \"$p\": " . why_text($S, $r)) unless $r->{ok};
  }
}

# ======================================================================================== build scripts
sub suffix_index {   # every component-aligned suffix of every file and directory: exact and lower-case
  my ($S) = @_;
  return $S->{sfx} if $S->{sfx};
  my (%exact, %lower, %dirs_of, %json, %dirseen);
  for my $p (@{$S->{all}}) {
    my @c = split m{/}, $p;
    for my $i (0 .. $#c) {
      my $suf = join '/', @c[$i .. $#c];
      $exact{$suf} = 1;
      $lower{lc $suf}{$p} = 1;
      $dirs_of{$suf}{ join '/', @c[0 .. $i - 1] } = 1;
    }
    for my $j (0 .. $#c - 1) {
      my $dp = join '/', @c[0 .. $j];
      next if $dirseen{$dp}++;
      for my $i (0 .. $j) { my $suf = join '/', @c[$i .. $j]; $exact{$suf} = 1; $lower{lc $suf}{$dp} = 1; }
    }
    push @{$json{$c[-1]}}, $p if $p =~ /\.json$/;
  }
  return $S->{sfx} = { exact => \%exact, lower => \%lower, dirs_of => \%dirs_of, json => \%json };
}
sub check_build_scripts {
  my ($S) = @_;
  my $idx = suffix_index($S);
  for my $bs (sort keys %{$S->{build_scripts}}) {
    my ($cdir, $sv) = @{$S->{build_scripts}{$bs}};
    my $text = read_text($S, $bs);
    next unless defined $text;
    my $X = lex_rust($text);
    my ($T, $V, $L) = @$X{qw(T V L)};
    my %lits;
    for my $i (0 .. $#$T) {
      next unless $T->[$i] eq 's';
      my $s = $V->[$i];
      $lits{$s} = 1;
      (my $p = $s) =~ s/^cargo::?[a-z-]+=//;
      $p =~ s/^"(.*)"$/$1/;
      next if $p eq '' || $p =~ /[\s{}*?]/ || $p =~ m{^/} || $p =~ /^[A-Za-z]:/;
      next unless $p =~ m{/} || $p =~ /\.(?:c|h|cc|cpp|hpp|S|s|asm|json|rs|toml|lock|txt|inc)$/;
      if ($p =~ /\\/) { finding($S, $sv, $bs, $L->[$i], "\"$s\" in a build script: " . bad_literal($p)); next; }
      $S->{st}{refs}++;
      if ($p =~ m{^\.\.?/}) {
        my $r = resolve($S, [ split m{/}, $cdir ], $p);
        finding($S, $sv, $bs, $L->[$i], "\"$s\" in a build script (run from $cdir/): " . why_text($S, $r)) unless $r->{ok};
        next;
      }
      (my $q = $p) =~ s{/+$}{};
      next if $idx->{exact}{$q};
      if (my $ci = $idx->{lower}{lc $q}) {
        finding($S, $sv, $bs, $L->[$i], "\"$s\" in a build script matches " . join(', ', map { "'$_'" } sort keys %$ci)
          . " only ignoring case (Linux is case-sensitive)");
      }
    }
    for my $s (sort keys %lits) {
      next unless $s =~ m{([^/\\]+\.json)$};
      check_source_lock($S, $sv, $bs, $_, \%lits) for @{$idx->{json}{$1} || []};
    }
  }
}
sub check_source_lock {
  my ($S, $sv, $bs, $json, $lits) = @_;
  return if $S->{locks_done}{"$json\0$sv"}++;
  my $text = read_text($S, $json);
  return unless defined $text;
  my (@stack, %sets, $ln);
  $ln = 0;
  for my $l (split /\n/, $text) {
    $ln++;
    if ($l =~ /^\s*"((?:[^"\\]|\\.)*)"\s*:\s*\{\s*(\}?)/) {
      push @stack, $1;
      if ($2) { pop @stack; next; }
      next;
    }
    if ($l =~ /^\s*\{\s*$/) { push @stack, ''; next; }
    if ($l =~ /^\s*\}/) { pop @stack; next; }
    if (@stack && $stack[-1] eq 'files' && $l =~ /^\s*"((?:[^"\\]|\\.)*)"\s*:\s*"([0-9a-fA-F]{64})"/) {
      my $k = $1;
      $k =~ s/\\(["\\\/])/$1/g;
      push @{$sets{ join "\0", grep { $_ ne '' } @stack }}, [$k, $ln];
    }
  }
  for my $set (sort keys %sets) {
    my @path = split /\0/, $set;
    next if @path > 1 && !$lits->{ $path[-2] };   # sources.<name>.files: only a <name> the build script spells
    my $label = join '.', @path;
    my $entries = $sets{$set};
    my $idx = suffix_index($S);
    my @ok = grep { $_->[0] !~ /\\/ } @$entries;
    finding($S, $sv, $json, $_->[1], "source lock entry \"$_->[0]\" (read by $bs): " . bad_literal($_->[0])) for grep { $_->[0] =~ /\\/ } @$entries;
    next unless @ok;
    my %score;
    for my $e (@ok) { $score{$_}++ for keys %{ $idx->{dirs_of}{ $e->[0] } || {} }; }
    my ($best) = sort { $score{$b} <=> $score{$a} || length($a) <=> length($b) || $a cmp $b } keys %score;
    if (defined $best && $score{$best} == @ok) {
      info($S, $json, $ok[0][1], "source lock \"$label\" (read by $bs): all " . scalar(@ok) . " files exist under $best/");
      next;
    }
    if (!defined $best) { finding($S, $sv, $json, $ok[0][1], "source lock \"$label\" (read by $bs): none of its " . scalar(@ok) . " files exists in the tree"); next; }
    my $pre = $best eq '' ? '' : "$best/";
    for my $e (@ok) {
      next if $idx->{dirs_of}{ $e->[0] }{$best};
      my $ci = $idx->{lower}{ lc "$pre$e->[0]" };
      finding($S, $sv, $json, $e->[1], "source lock entry \"$e->[0]\" (read by $bs) is not under $pre like the other entries"
        . ($ci ? ": the tree has " . join(', ', map { "'$_'" } sort keys %$ci) . " (the case differs; Linux is case-sensitive)" : ": no such file"));
    }
  }
}

# ======================================================================================== scripts, names, C
sub check_scripts {
  my ($S) = @_;
  for my $f (@{$S->{all}}) {
    my $is = $f =~ /\.(?:sh|bash|pl)$/;
    my $text;
    if (!$is && $f =~ m{^(?:build|package)/}) {
      $text = read_text($S, $f);
      $is = defined $text && (substr($text, 0, 2) eq '#!' || substr($text, 0, 5) eq "\xEF\xBB\xBF#!");
    }
    next unless $is;
    $text //= read_text($S, $f);
    next unless defined $text;
    $S->{st}{scripts}++;
    if ($text =~ /\r/) {
      my $ln = 1 + (substr($text, 0, $-[0]) =~ tr/\n//);
      finding($S, 'fail', $f, $ln, "carriage return (CRLF line ending): on Linux the interpreter sees it ('\$'\\r': command not found'); convert the script to LF");
    }
    if (substr($text, 0, 3) eq "\xEF\xBB\xBF") { finding($S, 'fail', $f, 1, "starts with a UTF-8 byte-order mark, so '#!' is not at the first byte"); }
    elsif (substr($text, 0, 2) ne '#!')       { finding($S, 'fail', $f, 1, "the first line is not a '#!' interpreter line"); }
  }
}
my %RESERVED = map { $_ => 1 } (qw(con prn aux nul), map { ("com$_", "lpt$_") } 1 .. 9);
sub name_findings {   # (list of relative paths) -> [ [path, message], ... ]
  my ($list) = @_;
  my %children;
  for my $p (@$list) {
    my @c = split m{/}, $p;
    my $d = '';
    for my $x (@c) { $children{$d}{$x} = 1; $d = $d eq '' ? $x : "$d/$x"; }
  }
  my @out;
  for my $d (sort keys %children) {
    my %by;
    push @{$by{lc $_}}, $_ for keys %{$children{$d}};
    for my $k (sort keys %by) {
      my @n = sort @{$by{$k}};
      next unless @n > 1;
      for my $x (@n) {
        push @out, [ ($d eq '' ? $x : "$d/$x"), "differs only by case from " . join(', ', map { "'" . ($d eq '' ? $_ : "$d/$_") . "'" } grep { $_ ne $x } @n)
          . " (a case-insensitive checkout, Windows or macOS, cannot hold both)" ];
      }
    }
    for my $x (sort keys %{$children{$d}}) {
      my $p = $d eq '' ? $x : "$d/$x";
      push @out, [$p, "name ends with a dot or a space (Windows cannot hold it)"] if $x =~ /[. ]$/;
      (my $stem = lc $x) =~ s/\..*$//;
      push @out, [$p, "Windows-reserved device name '$stem'"] if $RESERVED{$stem};
      push @out, [$p, "character that Windows does not allow in a file name"] if $x =~ /[<>:"|?*\\\x00-\x1f]/;
    }
  }
  return \@out;
}
sub check_c_includes {
  my ($S) = @_;
  my $idx = suffix_index($S);
  for my $f (grep { /\.(?:c|h|cc|cpp|cxx|hpp|hh|inc)$/i } @{$S->{all}}) {
    my $text = read_text($S, $f);
    next unless defined $text;
    my $ln = 0;
    for my $l (split /\n/, $text) {
      $ln++;
      next unless $l =~ /^\s*#\s*include\s*([<"])([^>"]+)[>"]/;
      my $inc = $2;
      if ($inc =~ /\\/) { finding($S, 'fail', $f, $ln, "#include \"$inc\": " . bad_literal($inc)); next; }
      (my $q = $inc) =~ s{^(?:\./)+}{};
      if ($q =~ m{(?:^|/)\.\.(?:/|$)}) {
        my $r = resolve($S, [ parent_comps($f) ], $q);
        finding($S, 'fail', $f, $ln, "#include \"$inc\": " . why_text($S, $r)) if !$r->{ok} && $r->{why} eq 'case';
        next;
      }
      next if $idx->{exact}{$q};
      my $ci = $idx->{lower}{lc $q} or next;
      finding($S, 'fail', $f, $ln, "#include \"$inc\" matches " . join(', ', map { "'$_'" } sort keys %$ci) . " only ignoring case (gcc on Linux will not find it)");
    }
  }
}

# ======================================================================================== selftest
sub st_write {
  my ($base, $files) = @_;
  mkdir $base unless -d $base;
  for my $p (sort keys %$files) {
    my @c = split m{/}, $p;
    my $d = $base;
    for my $x (@c[0 .. $#c - 1]) { $d .= "/$x"; mkdir $d unless -d $d; }
    open(my $fh, '>:raw', "$base/$p") or die "selftest: cannot write $base/$p: $!";
    print $fh $files->{$p};
    close $fh;
  }
}
sub st_git {   # git with its output discarded (the scratch paths hold no quote character)
  my $cmd = join ' ', 'git', map { "'$_'" } @_;
  return system("$cmd >/dev/null 2>&1") == 0;
}
sub st_rmtree {
  my ($p) = @_;
  if (-d $p && !-l $p) {
    opendir(my $dh, $p) or return;
    my @e = grep { $_ ne '.' && $_ ne '..' } readdir $dh;
    closedir $dh;
    st_rmtree("$p/$_") for @e;
    rmdir $p;
  } else { unlink $p; }
}
my $HEX = '0' x 64;
sub st_clean_tree {
  return (
    'good/Cargo.toml' => "[package]\nname = \"good\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\ndep = { path = \"../dep\" }\n\n"
      . "[dev-dependencies]\ngood = { path = \".\", features = [] }\n\n[target.'cfg(unix)'.dependencies]\nudep = { path = \"../udep\" }\n\n"
      . "[patch.crates-io]\npdep = { path = \"../pdep\" }\n\n[[example]]\nname = \"ex\"\n\n[[bin]]\nname = \"tool\"\npath = \"src/bin/tool.rs\"\n",
    'good/build.rs' => "fn main() {\n    let lock = std::path::Path::new(\"../good/data/lock.json\");\n    println!(\"cargo:rerun-if-changed=data/lock.json\");\n"
      . "    let _ = (lock, \"sub/inner.c\", \"src/a/sub.rs\", \"/std:c11\", \"{n}.c\");\n}\n",
    'good/data/lock.json' => "{\n  \"schema\": \"x\",\n  \"files\": {\n    \"src/lib.rs\": \"$HEX\",\n    \"src/a/sub.rs\": \"$HEX\"\n  },\n"
      . "  \"sources\": {\n    \"unread\": {\n      \"files\": {\n        \"no/such/file.c\": \"$HEX\"\n      }\n    }\n  }\n}\n",
    'good/src/lib.rs' => <<'EOF',
//! Lexer torture: nothing in a comment, a string, a raw string or a char literal is a reference.
// #[path = "nope_comment.rs"] mod nope_comment;
/* outer /* nested #[path = "nope_block.rs"] mod nope_block; */ still a comment { */
pub const S1: &str = "#[path = \"nope_string.rs\"] mod nope_string; {";
pub const S2: &str = r#"include_str!("nope_raw.txt") } "#;
pub const S3: &[u8] = br##"mod nope_raw_bytes; "# }"##;
pub const C1: char = '{';
pub const C2: char = '"';
pub const C3: u8 = b'}';
pub const C4: char = '\'';
pub fn lifetimes<'a>(x: &'a str) -> &'a str { 'outer: loop { break 'outer; } x }
pub fn r#match() {}
macro_rules! inc { ($p:expr) => { include_str!($p) }; }
mod a;
#[path = "b_impl.rs"]
mod b;
mod inl {
    #[path = "x.rs"]
    mod x;
}
#[path = "pdir"]
mod with_dir {
    mod deep;
}
#[cfg(test)]
#[path = "../tests/support/shared.rs"]
mod shared;
pub const FIX: &str = include_str!("../data/fixture.txt");
pub const MAN: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/data/fixture.txt"));
#[cfg(windows)]
mod win_only;
pub mod plain_dir;
#[cfg_attr(unix, path = "unix_impl.rs")]
mod plat;
#[cfg_attr(windows, path = "nonexistent_win.rs")]
mod plat2;
EOF
    'good/src/a.rs' => "mod sub;\nmod t {\n    #[path = \"y.rs\"]\n    mod y;\n}\n#[path = \"sibling.rs\"]\nmod sibling;\n#[path = \"dir_a\"]\nmod with_path {\n    #[path = \"z.rs\"]\n    mod z;\n}\n",
    'good/src/a/sub.rs' => "", 'good/src/a/t/y.rs' => "", 'good/src/sibling.rs' => "", 'good/src/dir_a/z.rs' => "",
    'good/src/b_impl.rs' => "mod c;\nmod inl2 {\n    #[path = \"w.rs\"]\n    mod w;\n}\n",
    'good/src/c.rs' => "mod d;\n", 'good/src/c/d.rs' => "", 'good/src/inl2/w.rs' => "", 'good/src/inl/x.rs' => "",
    'good/src/pdir/deep.rs' => "", 'good/src/win_only.rs' => "", 'good/src/plain_dir/mod.rs' => "", 'good/src/unix_impl.rs' => "",
    'good/src/plat2.rs' => "", 'good/src/bin/tool.rs' => "fn main() {}\n",
    'good/tests/it.rs' => "#[path = \"support/shared.rs\"]\nmod shared;\nmod holder {\n    include!(\"support/inc.rs\");\n}\n#[test]\nfn t() {}\n",
    'good/tests/support/shared.rs' => "", 'good/tests/support/inc.rs' => "mod inc_child;\nmod q {\n    #[path = \"w2.rs\"]\n    mod w2;\n}\n",
    'good/tests/support/inc_child.rs' => "", 'good/tests/support/q/w2.rs' => "",
    'good/examples/ex.rs' => "fn main() {}\n", 'good/data/fixture.txt' => "x\n",
    'good/c/sub/inner.c' => "#include \"inner.h\"\n#include <stdio.h>\n", 'good/c/sub/inner.h' => "\n",
    'dep/Cargo.toml' => "[package]\nname = \"dep\"\nversion = \"0.1.0\"\n", 'dep/src/lib.rs' => "mod m;\n", 'dep/src/m.rs' => "",
    'udep/Cargo.toml' => "[package]\nname = \"udep\"\nversion = \"0.1.0\"\n", 'udep/src/lib.rs' => "",
    'pdep/Cargo.toml' => "[package]\nname = \"pdep\"\nversion = \"0.1.0\"\n", 'pdep/src/lib.rs' => "",
    'win/Cargo.toml' => "[package]\nname = \"win\"\nversion = \"0.1.0\"\n", 'win/src/main.rs' => "fn main() { let _ = include_str!(\"data.txt\"); }\n",
    'win/src/data.txt' => "x\n",
    'build/ok.sh' => "#!/usr/bin/env bash\necho ok\n", 'build/tool.pl' => "#!/usr/bin/env perl\nprint 1;\n",
  );
}
sub st_bad_tree {
  return (
    'bad/Cargo.toml' => "[package]\nname = \"bad\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\ndep = { path = \"../Dep\" }\n"
      . "gone = { path = \"../gone\" }\nnomanifest = { path = \"../nomanifest\" }\nback = { path = \"..\\\\dep\" }\n\n"
      . "[[bin]]\nname = \"tool\"\npath = \"src/bin/Tool.rs\"\n\n[[example]]\nname = \"missing_example\"\n",
    'bad/src/lib.rs' => <<'EOF',
mod a;
mod Util;
mod absent;
#[path = "Helper.rs"]
mod helper;
#[path = "sub\\file.rs"]
mod back;
pub const X: &str = include_str!("../data/Fixture.txt");
pub const Y: &[u8] = include_bytes!("../data/none.bin");
pub const Z: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Data/fixture.txt"));
pub const W: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "data/fixture.txt"));
#[cfg(windows)]
mod win_missing;
#[cfg(target_os = "linux")]
mod linux_missing;
mod both;
EOF
    'bad/src/a.rs' => "#[cfg(test)]\nmod tests {\n    #[path = \"../../../tests/support/s.rs\"]\n    mod s;\n}\nmod inl {\n    mod deeper;\n}\n",
    'bad/src/util.rs' => "", 'bad/src/helper.rs' => "", 'bad/src/both.rs' => "", 'bad/src/both/mod.rs' => "", 'bad/src/bin/tool.rs' => "fn main() {}\n",
    'bad/tests/support/s.rs' => "", 'bad/data/fixture.txt' => "x\n",
    'bad/build.rs' => "fn main() {\n    let _ = std::path::Path::new(\"../bad/data/Lock.json\");\n    let _ = \"SUB/inner.c\";\n    let _ = std::path::Path::new(\"lock.json\");\n}\n",
    'bad/data/lock.json' => "{\n  \"files\": {\n    \"src/lib.rs\": \"$HEX\",\n    \"src/A.rs\": \"$HEX\",\n    \"src\\\\util.rs\": \"$HEX\"\n  }\n}\n",
    'bad/c/sub/inner.c' => "#include \"INNER.h\"\n", 'bad/c/sub/inner.h' => "\n",
    'dep/Cargo.toml' => "[package]\nname = \"dep\"\nversion = \"0.1.0\"\n", 'dep/src/lib.rs' => "",
    'nomanifest/cargo.toml' => "[package]\nname = \"nomanifest\"\n", 'nomanifest/src/lib.rs' => "",
    'win/Cargo.toml' => "[package]\nname = \"win\"\nversion = \"0.1.0\"\n", 'win/src/main.rs' => "fn main() { let _ = include_str!(\"Data.txt\"); }\n",
    'win/src/data.txt' => "x\n",
    'build/crlf.sh' => "#!/bin/sh\r\necho x\r\n", 'build/noshebang.sh' => "echo x\n", 'package/bom.sh' => "\xEF\xBB\xBF#!/bin/sh\necho x\n",
  );
}
sub selftest {
  my $tmp = $ENV{TMPDIR} || $ENV{TEMP} || $ENV{TMP} || '/tmp';
  $tmp =~ s{\\}{/}g;
  my $base = "$tmp/check-source-paths-selftest-$$-" . time;
  mkdir $base or do { print STDERR "$ME: cannot create $base: $!\n"; return 2; };
  my ($pass, $fail) = (0, 0);
  my $ok = sub { my ($c, $what) = @_; if ($c) { $pass++; print "  ok    $what\n"; } else { $fail++; print "  FAIL  $what\n"; } return $c; };
  my $dump = sub { my ($S) = @_; print "        | $_->{file}:$_->{line}: [$_->{sev}] $_->{msg}\n" for findings_sorted($S); };
  my %opt = (nogit => 1, fail_roots => ['good', 'bad', 'g'], win_roots => ['win']);
  print "$ME selftest in $base\n";

  # 1. a clean tree: no finding, and every file is reached through the modelled rule (each file is the only one
  #    that could satisfy its reference, so reaching it confirms the rule).
  my %clean = st_clean_tree();
  st_write("$base/clean", \%clean);
  my $S = run_checks("$base/clean", \%opt);
  my @bad = grep { $_->{sev} ne 'info' } findings_sorted($S);
  $ok->(!@bad, "clean tree: no finding (lexer torture, every module rule, Cargo paths, scripts, C includes, source lock)") or $dump->($S);
  my @reach = qw(good/src/a/sub.rs good/src/a/t/y.rs good/src/sibling.rs good/src/dir_a/z.rs good/src/c.rs good/src/c/d.rs
    good/src/inl2/w.rs good/src/inl/x.rs good/src/pdir/deep.rs good/src/win_only.rs good/src/plain_dir/mod.rs good/src/unix_impl.rs
    good/src/plat2.rs good/tests/support/shared.rs good/tests/support/inc_child.rs good/tests/support/q/w2.rs good/examples/ex.rs
    good/src/bin/tool.rs good/build.rs dep/src/m.rs udep/src/lib.rs pdep/src/lib.rs win/src/main.rs);
  my @miss = grep { !$S->{st}{rust}{$_} } @reach;
  $ok->(!@miss, "clean tree: all " . scalar(@reach) . " module sources reached by the rustc rules" . (@miss ? " (missed: @miss)" : ''));
  $ok->(scalar(grep { $_->{sev} eq 'info' && $_->{msg} =~ /CARGO_MANIFEST_DIR.*checked against the crate root good\// } values %{$S->{F}}),
        "clean tree: the concat!(env!(\"CARGO_MANIFEST_DIR\"), ..) include is listed (info) and checked against the crate root");
  $ok->(scalar(grep { $_->{sev} eq 'info' && $_->{msg} =~ /argument is neither a string literal/ } values %{$S->{F}}),
        "clean tree: an include argument built from a macro variable is reported as not checked (info)");
  $ok->(scalar(grep { $_->{sev} eq 'info' && $_->{msg} =~ /all 2 files exist under good\// } values %{$S->{F}}),
        "clean tree: the source lock resolves under good/ and its unread source entry is ignored");

  # 2. every finding class is reported in the bad tree.
  my %badt = st_bad_tree();
  st_write("$base/bad", \%badt);
  $S = run_checks("$base/bad", \%opt);
  my @expect = (
    ['bad/src/a.rs', 3, 'fail', qr/^#\[path = "\.\.\/\.\.\/\.\.\/tests\/support\/s\.rs"\] inside inline module `tests` resolves from bad\/src\/a\/tests\/.*'bad\/src\/a' does not exist.*ENOENT/, '1 inline-module #[path] with ..'],
    ['bad/src/a.rs', 7, 'fail', qr/^mod deeper; inside inline module `inl`: the module directory: 'bad\/src\/a' does not exist/, '3 plain mod inside an inline module of a non-mod-rs file'],
    ['bad/src/lib.rs', 2, 'fail', qr/^mod Util;: 'bad\/src\/Util\.rs' does not exist: the directory holds 'bad\/src\/util\.rs'/, '3 mod with the wrong case'],
    ['bad/src/lib.rs', 3, 'fail', qr/^mod absent;: neither bad\/src\/absent\.rs nor bad\/src\/absent\/mod\.rs exists/, '3 mod without a file'],
    ['bad/src/lib.rs', 4, 'fail', qr/^#\[path = "Helper\.rs"\]: 'bad\/src\/Helper\.rs' does not exist: the directory holds 'bad\/src\/helper\.rs'/, '1 #[path] with the wrong case'],
    ['bad/src/lib.rs', 6, 'fail', qr/^#\[path = "sub\\file\.rs"\]: backslash/, '5 backslash in #[path]'],
    ['bad/src/lib.rs', 8, 'fail', qr/^include_str!\("\.\.\/data\/Fixture\.txt"\): .*the case differs/, '2 include_str! with the wrong case'],
    ['bad/src/lib.rs', 9, 'fail', qr/^include_bytes!\("\.\.\/data\/none\.bin"\): 'bad\/data\/none\.bin' does not exist/, '2 include_bytes! without a file'],
    ['bad/src/lib.rs', 10, 'fail', qr/^include_str!\(concat!\(env!\("CARGO_MANIFEST_DIR"\), "\/Data\/fixture\.txt"\)\): 'bad\/Data' does not exist: the directory holds 'bad\/data'/, '2 CARGO_MANIFEST_DIR include with the wrong case'],
    ['bad/src/lib.rs', 11, 'fail', qr/must start with '\/'/, "2 CARGO_MANIFEST_DIR include without '/'"],
    ['bad/src/lib.rs', 13, 'win', qr/^mod win_missing;: neither/, 'cfg(windows) module without a file is windows-only'],
    ['bad/src/lib.rs', 15, 'fail', qr/^mod linux_missing;: neither/, 'cfg(target_os = "linux") module without a file fails'],
    ['bad/src/lib.rs', 16, 'fail', qr/^mod both;: both bad\/src\/both\.rs and bad\/src\/both\/mod\.rs exist/, '3 ambiguous mod'],
    ['bad/Cargo.toml', 7, 'fail', qr/^path = "\.\.\/Dep" \(dep 'dep' in \[dependencies\]\): 'Dep' does not exist: the directory holds 'dep'/, '4 Cargo path dependency with the wrong case'],
    ['bad/Cargo.toml', 8, 'fail', qr/^path = "\.\.\/gone" .*'gone' does not exist/, '4 Cargo path dependency without a directory'],
    ['bad/Cargo.toml', 9, 'fail', qr/nomanifest\/ has no Cargo\.toml \(it has 'cargo\.toml'/, '4 Cargo path dependency without an exact Cargo.toml'],
    ['bad/Cargo.toml', 10, 'fail', qr/^path = "\.\.\\dep" .*backslash/, '5 backslash in a Cargo path'],
    ['bad/Cargo.toml', 14, 'fail', qr/^\[\[bin\]\] path = "src\/bin\/Tool\.rs": .*the case differs/, '4 [[bin]] path with the wrong case'],
    ['bad/Cargo.toml', 16, 'fail', qr/^\[\[example\]\] name = "missing_example": no target file/, '4 [[example]] without a file'],
    ['build/crlf.sh', 1, 'fail', qr/^carriage return/, '6 CRLF shell script'],
    ['build/noshebang.sh', 1, 'fail', qr/is not a '#!' interpreter line/, '6 shell script without #!'],
    ['package/bom.sh', 1, 'fail', qr/byte-order mark/, '6 shell script with a byte-order mark'],
    ['bad/build.rs', 2, 'fail', qr/^"\.\.\/bad\/data\/Lock\.json" in a build script \(run from bad\/\): .*the case differs/, '8 build-script path with the wrong case'],
    ['bad/build.rs', 3, 'fail', qr/^"SUB\/inner\.c" in a build script matches 'bad\/c\/sub\/inner\.c'|^"SUB\/inner\.c" in a build script matches .*only ignoring case/, '8 build-script fragment that matches only ignoring case'],
    ['bad/data/lock.json', 4, 'fail', qr/^source lock entry "src\/A\.rs" .*'bad\/src\/a\.rs'/, '8 source-lock entry with the wrong case'],
    ['bad/data/lock.json', 5, 'fail', qr/^source lock entry "src\\util\.rs" .*backslash/, '8 source-lock entry with a backslash'],
    ['bad/c/sub/inner.c', 1, 'fail', qr/^#include "INNER\.h" matches 'bad\/c\/sub\/inner\.h' only ignoring case/, '9 C include with the wrong case'],
    ['win/src/main.rs', 1, 'win', qr/^include_str!\("Data\.txt"\): .*the case differs/, 'a finding in the Windows-only crate is windows-only'],
  );
  for my $x (@expect) {
    my ($file, $line, $sev, $re, $what) = @$x;
    my $hit = grep { $_->{file} eq $file && $_->{line} == $line && $_->{sev} eq $sev && $_->{msg} =~ $re } values %{$S->{F}};
    $ok->($hit, "bad tree: $what ($file:$line, $sev)");
  }
  my $nbad = grep { $_->{sev} ne 'info' } values %{$S->{F}};
  $ok->($nbad == @expect, "bad tree: exactly the " . scalar(@expect) . " expected findings (got $nbad)") or $dump->($S);
  $ok->(count_sev($S, 'fail') > 0, "bad tree: the run fails");

  # 3. names (a case-insensitive host cannot create these files, so the rule is checked on a list).
  my $nf = name_findings([qw(docs/A.md docs/a.md x/aux.txt y/trail. w/a:b Dir/f dir/g ok/fine.rs), 'z/space ']);
  my %got = map { ("$_->[0]|" . ($_->[1] =~ /^differs only by case/ ? 'case' : $_->[1] =~ /dot or a space/ ? 'trail' : $_->[1] =~ /reserved/ ? 'reserved' : 'char')) => 1 } @$nf;
  for my $k (qw(docs/A.md|case docs/a.md|case Dir|case dir|case x/aux.txt|reserved y/trail.|trail w/a:b|char), 'z/space |trail') {
    $ok->($got{$k}, "7 names: $k");
  }
  $ok->(@$nf == 8, "7 names: nothing else (got " . scalar(@$nf) . ")");

  # 4. git mode: the index is the tree (an untracked file or a stray local directory does not count).
  my $gitok = st_git('--version');
  if ($gitok) {
    my %g = ('g/Cargo.toml' => "[package]\nname = \"g\"\nversion = \"0.1.0\"\n",
             'g/src/lib.rs' => "pub const A: &str = include_str!(\"../data/tracked.txt\");\npub const B: &str = include_str!(\"../data/untracked.txt\");\n"
                               . "pub const C: &str = include_str!(\"../stray/../data/tracked.txt\");\n",
             'g/data/tracked.txt' => "x\n", 'g/data/untracked.txt' => "x\n", 'g/stray/junk.txt' => "x\n");
    st_write("$base/git", \%g);
    my $q = st_git('-C', "$base/git", 'init', '-q')
         && st_git('-C', "$base/git", '-c', 'core.autocrlf=false', 'add', 'g/Cargo.toml', 'g/src/lib.rs', 'g/data/tracked.txt');
    if ($q) {
      $S = run_checks("$base/git", { %opt, nogit => 0 });
      $ok->($S->{mode} eq 'git', "git mode: the index is used");
      $ok->(scalar(grep { $_->{file} eq 'g/src/lib.rs' && $_->{line} == 2 && $_->{sev} eq 'fail' && $_->{msg} =~ /untracked/ } values %{$S->{F}}), "git mode: a reference to an untracked file fails");
      $ok->(scalar(grep { $_->{file} eq 'g/src/lib.rs' && $_->{line} == 3 && $_->{sev} eq 'fail' && $_->{msg} =~ /'g\/stray' does not exist in the git index/ } values %{$S->{F}}), "git mode: '..' through an untracked directory fails");
      $ok->(!grep({ $_->{file} eq 'g/src/lib.rs' && $_->{line} == 1 } values %{$S->{F}}), "git mode: a tracked file passes");
    } else { print "  SKIP  git mode (git init/add failed in the scratch tree)\n"; }
  } else { print "  SKIP  git mode (git is not on PATH)\n"; }

  print "SELFTEST ", ($fail ? "FAILED" : "PASSED"), ": $pass check(s) passed, $fail failed\n";
  if ($fail) { print "scratch trees kept in $base\n"; } else { st_rmtree($base); }
  return $fail ? 1 : 0;
}

exit(main());
