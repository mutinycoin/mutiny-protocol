#!/usr/bin/env perl
# Host-independence TRIPWIRE for non-test consensus and node code (TPM admission package,
# docs/BUILD-CONFIGURATIONS-V1.md section 13). Called by build/check-shipping-config.sh; the Rust
# twin is consensus/tests/host_independence_guard.rs. Both read ONE rule set
# (build/host-independence-rules.txt: rules and the explicit allow-list), apply it with the SAME
# model of test code, and must reach the expected verdict on every probe of
# build/host-independence-probes.txt.
#
# This is a tripwire, not a proof: it matches spellings in source text, so a spelling the rules do
# not list, a computed path, a new dependency or a helper process can still reach the host. The
# property (validator-local maps, verifiers, pins and host facts cannot change consensus acceptance)
# is tested separately by the pin-invariance tests.
#
# Model of test code:
#  * comments are removed; string, raw-string, byte-string and char literals are kept (they can name
#    a host file) but never count as code structure;
#  * an item preceded by an attribute whose whitespace-free text starts with `#[cfg(test)]` or
#    `#[cfg(all(test,` is test code up to its end: the first `;` or `,` at its own nesting level,
#    the `}` that closes its body, or the point where an enclosing block or bracket closes. Code
#    after that point, even on the same line, is shipped code. `#[cfg(any(test, ...))]` is shipped;
#  * a file included by a test-only `#[path = ".."] mod`, and transitively every file such a test
#    file includes by `#[path]`, is a test file and is not scanned.
# Known limits: the brace/bracket model does not understand macro_rules! bodies or generic angle
# brackets (a `,` inside `<..>` ends a test item early: code is then treated as SHIPPED, the safe
# direction); `#![cfg(test)]` files are scanned as shipped code (safe direction).
#
# Usage: perl build/check-host-independence.pl [--root DIR] [--selftest | --dump]
#   default     scan consensus/src and node/src; print "FINDING <file>:<line>: ..." per finding
#               and "SUMMARY ..."; exit 0 only if there is no finding (stale allow entries count).
#   --selftest  run every probe; print "PROBE <id> expected <X> got <Y> ok|MISMATCH"; exit 0 only
#               if every probe reaches its expected verdict.
#   --dump      print "<file>:<line>: <code>" for every non-test line (model comparison aid).
use strict;
use warnings;
use Cwd ();
use Encode ();
use File::Spec ();

my ($root, $mode) = (undef, 'scan');
while (@ARGV) {
    my $a = shift @ARGV;
    if ($a eq '--root') { $root = shift @ARGV; }
    elsif ($a eq '--selftest') { $mode = 'selftest'; }
    elsif ($a eq '--dump') { $mode = 'dump'; }
    else { die "unknown argument $a\n"; }
}
unless (defined $root) {
    my ($vol, $dir) = File::Spec->splitpath(File::Spec->rel2abs($0));
    $root = File::Spec->catpath($vol, File::Spec->catdir($dir, File::Spec->updir), '');
}
$root = Cwd::abs_path($root) // die "root not found\n";
my @SCAN = ('consensus/src', 'node/src');

# The lexer and the model of test code (described above) are shared with build/check-signing-calls.pl:
# build/rust-source-model.pl, loaded from this script's own directory.
use FindBin ();
BEGIN {
    require "$FindBin::Bin/rust-source-model.pl";
    no strict 'refs';
    *{"main::$_"} = \&{"RustSourceModel::$_"}
        for qw(slurp lex attribute_at test_only item_end path_of regions all_paths non_test_lines);
}

# ---- rules ---------------------------------------------------------------------------------------
my (@rules, @allows);
for my $raw (split /\n/, slurp("$root/build/host-independence-rules.txt")) {
    (my $l = $raw) =~ s/\r$//;
    next if $l =~ /^\s*(#|$)/;
    if ($l =~ /^rule\s+(\S+)\s+(sub|word|iword|macro)\s+(\S.*?)\s*$/) { push @rules, { class => $1, kind => $2, text => $3 }; }
    elsif ($l =~ /^allow\s+(\S+)\s+(\S.*?)\s*$/) { push @allows, { file => $1, fragment => $2, used => 0 }; }
    else { die "build/host-independence-rules.txt: malformed line: $l\n"; }
}
die "no rules\n" unless @rules;
sub hits {
    my ($r, $code) = @_;
    my ($kind, $text) = ($r->{kind}, $r->{text});
    return index(lc $code, lc $text) >= 0 if $kind eq 'sub';
    if ($kind eq 'macro') { return $code =~ /(?<![A-Za-z0-9_])\Q$text\E\s*!/ ? 1 : 0; }
    for my $w (split /[^A-Za-z0-9_]+/, $code) {
        return 1 if $kind eq 'word' && $w eq $text;
        return 1 if $kind eq 'iword' && lc $w eq lc $text;
    }
    return 0;
}
# Findings for one file text scanned as the repository-relative path $rel.
sub findings {
    my ($rel, $text) = @_;
    my ($lines) = non_test_lines($text);
    my @mine = grep { $_->{file} eq $rel } @allows;
    my @out;
    for my $l (@$lines) {
        my ($ln, $code) = @$l;
        my $rest = $code;
        for my $a (@mine) {
            next unless index($code, $a->{fragment}) >= 0;
            $a->{used} = 1 if grep { hits($_, $code) } @rules;
            $rest =~ s/\Q$a->{fragment}\E//g;
        }
        for my $r (@rules) {
            push @out, "$rel:$ln: $r->{class} (rule $r->{kind} '$r->{text}'): $code" if hits($r, $rest);
        }
    }
    return @out;
}

# ---- probes --------------------------------------------------------------------------------------
if ($mode eq 'selftest') {
    my (@probes, $cur);
    for my $raw (split /\n/, slurp("$root/build/host-independence-probes.txt")) {
        (my $l = $raw) =~ s/\r$//;
        if ($l =~ /^=== (\S+) (PASS|FAIL)(?: @(\S+))? (.*)$/) {
            $cur = { id => $1, want => $2, file => $3 // 'node/src/guard_probe.rs', what => $4, text => '' };
            push @probes, $cur; next;
        }
        next unless $cur;
        $cur->{text} .= "$l\n";
    }
    die "no probes\n" unless @probes;
    my $bad = 0;
    for my $p (@probes) {
        my @f = findings($p->{file}, $p->{text});
        my $got = @f ? 'FAIL' : 'PASS';
        my $ok = $got eq $p->{want};
        $bad++ unless $ok;
        printf "PROBE %s expected %s got %s %s (%s)\n", $p->{id}, $p->{want}, $got, $ok ? 'ok' : 'MISMATCH', $p->{what};
    }
    printf "SELFTEST %d probe(s), %d mismatch(es)\n", scalar @probes, $bad;
    exit($bad ? 1 : 0);
}

# ---- the shipped tree ----------------------------------------------------------------------------
my @files;
sub walk {
    my ($dir) = @_;
    opendir(my $d, $dir) or die "$dir: $!\n";
    for my $e (sort grep { $_ ne '.' && $_ ne '..' } readdir $d) {
        my $p = "$dir/$e";
        if (-d $p) { walk($p); } elsif ($e =~ /\.rs$/) { push @files, $p; }
    }
    closedir $d;
}
walk("$root/$_") for @SCAN;
die "too few Rust files under @SCAN\n" if @files < 100;
sub canon { my ($base, $p) = @_; my $full = "$base/$p"; return -e $full ? Cwd::abs_path($full) : undef; }
sub dirname_of { my ($p) = @_; (my $d = $p) =~ s{/[^/]*$}{}; return $d; }
my (%text, %test_file, @queue);
for my $f (@files) {
    $text{$f} = slurp($f);
    my (undef, $paths) = non_test_lines($text{$f});
    for my $p (@$paths) {
        my $c = canon(dirname_of($f), $p);
        if (defined $c && !$test_file{$c}++) { push @queue, $c; }
    }
}
while (defined(my $t = shift @queue)) {
    next unless -f $t;
    my ($L, $C, $T) = lex(slurp($t));
    for my $p (all_paths($C, $T)) {
        my $c = canon(dirname_of($t), $p);
        if (defined $c && !$test_file{$c}++) { push @queue, $c; }
    }
}
my @shipped = grep { !$test_file{Cwd::abs_path($_)} } @files;
my $rel = sub { my ($f) = @_; (my $r = $f) =~ s{^\Q$root\E/}{}; return $r; };
if ($mode eq 'dump') {
    for my $f (@shipped) {
        my ($lines) = non_test_lines($text{$f});
        print $rel->($f), ":$_->[0]: $_->[1]\n" for @$lines;
    }
    exit 0;
}
my @found;
my $nlines = 0;
for my $f (@shipped) {
    my ($lines) = non_test_lines($text{$f});
    $nlines += @$lines;
    push @found, findings($rel->($f), $text{$f});
}
for my $a (@allows) {
    push @found, "build/host-independence-rules.txt: stale allow entry (no non-test line of $a->{file} needs it): $a->{fragment}" unless $a->{used};
}
print "FINDING $_\n" for @found;
printf "SUMMARY scanned %d shipped file(s) (%d test file(s) excluded), %d non-test line(s), %d rule(s), %d allow entr%s: %d finding(s)\n",
    scalar @shipped, scalar(@files) - scalar(@shipped), $nlines, scalar @rules, scalar @allows, @allows == 1 ? 'y' : 'ies', scalar @found;
die "too few shipped lines scanned: $nlines\n" if $nlines < 10000;
exit(@found ? 1 : 0);
