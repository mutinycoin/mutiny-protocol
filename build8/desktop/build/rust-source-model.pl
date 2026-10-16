#!/usr/bin/env perl
# The model of Rust source text shared by the build TRIPWIRES: build/check-host-independence.pl
# (non-test consensus and node code) and build/check-signing-calls.pl (non-test wallet-core and
# desktop code). Loaded with `require`; it defines package RustSourceModel and runs nothing.
# The functions below were moved here unchanged from build/check-host-independence.pl (fixes of the
# independent wallet review, MAJOR-2), so that both tripwires read source text the same way; that
# script's model description applies:
#
#  * comments are removed; string, raw-string, byte-string and char literals are kept (they can name
#    a host file) but never count as code structure (`lex` flags every literal character);
#  * an item preceded by an attribute whose whitespace-free text starts with `#[cfg(test)]` or
#    `#[cfg(all(test,` is test code up to its end: the first `;` or `,` at its own nesting level,
#    the `}` that closes its body, or the point where an enclosing block or bracket closes. Code
#    after that point, even on the same line, is shipped code. `#[cfg(any(test, ...))]` is shipped;
#  * `regions` also returns the `#[path]` values of test-only items (a caller treats those files,
#    transitively, as test files).
# Known limits: the brace/bracket model does not understand macro_rules! bodies or generic angle
# brackets (a `,` inside `<..>` ends a test item early: code is then treated as SHIPPED, the safe
# direction); `#![cfg(test)]` files are scanned as shipped code (safe direction).
package RustSourceModel;
use strict;
use warnings;
use Encode ();

sub slurp {
    my ($path) = @_;
    open(my $h, '<:raw', $path) or die "$path: $!\n";
    local $/; my $bytes = <$h>; close $h;
    return Encode::decode('UTF-8', $bytes);
}

# ---- lexer: (lines, chars, literal flags); comments dropped -------------------------------------
sub lex {
    my @c = split //, $_[0];
    my (@L, @C, @T);
    my ($n, $line, $i, $state, $depth, $hashes) = (scalar @c, 1, 0, 'code', 0, 0);
    my $emit = sub { push @L, $line; push @C, $_[0]; push @T, $_[1]; };
    while ($i < $n) {
        my $x = $c[$i];
        my $nx = $i + 1 < $n ? $c[$i + 1] : "\0";
        if ($x eq "\n") {
            $state = 'code' if $state eq 'line';
            $line++; $i++; next;
        }
        if ($state eq 'line') { $i++; next; }
        if ($state eq 'block') {
            if ($x eq '*' && $nx eq '/') { $depth--; $state = 'code' if $depth == 0; $i += 2; next; }
            if ($x eq '/' && $nx eq '*') { $depth++; $i += 2; next; }
            $i++; next;
        }
        if ($state eq 'str') {
            $emit->($x, 1);
            if ($x eq '\\') {
                if ($nx eq "\n") { $line++; } elsif ($i + 1 < $n) { $emit->($nx, 1); }
                $i += 2; next;
            }
            $state = 'code' if $x eq '"';
            $i++; next;
        }
        if ($state eq 'raw') {
            $emit->($x, 1);
            if ($x eq '"') {
                my $ok = 1;
                for my $k (1 .. $hashes) { $ok = 0 unless $i + $k < $n && $c[$i + $k] eq '#'; }
                if ($ok) { $emit->('#', 1) for 1 .. $hashes; $i += $hashes; $state = 'code'; }
            }
            $i++; next;
        }
        if ($x eq '/' && $nx eq '/') { $state = 'line'; $i += 2; next; }
        if ($x eq '/' && $nx eq '*') { $state = 'block'; $depth = 1; $i += 2; next; }
        if ($x eq '"') { $emit->($x, 1); $state = 'str'; $i++; next; }
        my $after_word = $i > 0 && $c[$i - 1] =~ /^[A-Za-z0-9_]$/;
        if (($x eq 'r' || ($x eq 'b' && $nx eq 'r')) && !$after_word) {
            my $start = $x eq 'b' ? $i + 2 : $i + 1;
            my $j = $start;
            $j++ while $j < $n && $c[$j] eq '#';
            if ($j < $n && $c[$j] eq '"') {
                $emit->($c[$_], 1) for $i .. $j;
                $hashes = $j - $start; $state = 'raw'; $i = $j + 1; next;
            }
            $emit->($x, 0); $i++; next;
        }
        if ($x eq "'") {
            if ($nx eq '\\') {
                my $j = $i + 3;
                $j++ while $j < $n && $c[$j] ne "'" && $c[$j] ne "\n";
                my $end = ($j < $n && $c[$j] eq "'") ? $j : $j - 1;
                $emit->($c[$_], 1) for $i .. $end;
                $i = $end + 1; next;
            }
            if ($i + 2 < $n && $c[$i + 2] eq "'") { $emit->($c[$_], 1) for $i .. $i + 2; $i += 3; next; }
            $emit->($x, 0); $i++; next;
        }
        $emit->($x, 0); $i++;
    }
    return (\@L, \@C, \@T);
}

# ---- attributes, test items, regions -------------------------------------------------------------
# Outer attribute at $i: (end index, whitespace-free text, literal characters), or () if none.
sub attribute_at {
    my ($C, $T, $i) = @_;
    my $n = @$C;
    return () unless $i < $n && !$T->[$i] && $C->[$i] eq '#';
    my $j = $i + 1;
    $j++ while $j < $n && !$T->[$j] && $C->[$j] =~ /\s/;
    return () unless $j < $n && !$T->[$j] && $C->[$j] eq '[';
    my ($depth, $compact, $lit) = (0, '#', '');
    for (my $k = $j; $k < $n; $k++) {
        my $c = $C->[$k];
        if ($T->[$k]) { $compact .= $c; $lit .= $c; next; }
        $compact .= $c unless $c =~ /\s/;
        if ($c eq '[') { $depth++; }
        elsif ($c eq ']') { $depth--; return ($k + 1, $compact, $lit) if $depth == 0; }
    }
    return ($n, $compact, $lit);
}
sub test_only { my ($c) = @_; return index($c, '#[cfg(test)]') == 0 || index($c, '#[cfg(all(test,') == 0; }
# First index after the item that starts at $i.
sub item_end {
    my ($C, $T, $i) = @_;
    my ($n, $brace, $paren) = (scalar @$C, 0, 0);
    for (my $k = $i; $k < $n; $k++) {
        next if $T->[$k];
        my $c = $C->[$k];
        if ($c eq '(' || $c eq '[') { $paren++; }
        elsif ($c eq ')' || $c eq ']') { return $k if $paren == 0 && $brace == 0; $paren-- if $paren > 0; }
        elsif ($c eq '{') { $brace++; }
        elsif ($c eq '}') { return $k if $brace == 0; $brace--; return $k + 1 if $brace == 0 && $paren == 0; }
        elsif ($c eq ';' || $c eq ',') { return $k + 1 if $brace == 0 && $paren == 0; }
    }
    return $n;
}
sub path_of { my ($compact, $lit) = @_; return index($compact, '#[path=') == 0 && $lit =~ /"([^"]*)"/ ? $1 : undef; }
# (test flags per character, #[path] values attached to test-only items)
sub regions {
    my ($C, $T) = @_;
    my $n = @$C;
    my @test = (0) x $n;
    my @paths;
    my $i = 0;
    while ($i < $n) {
        my ($end, $compact) = attribute_at($C, $T, $i);
        if (!defined $end) { $i++; next; }
        if (!test_only($compact)) { $i = $end; next; }
        my $j = $end;
        while (1) {
            $j++ while $j < $n && !$T->[$j] && $C->[$j] =~ /\s/;
            my ($e2, $c2, $l2) = attribute_at($C, $T, $j);
            last unless defined $e2;
            my $p = path_of($c2, $l2);
            push @paths, $p if defined $p;
            $j = $e2;
        }
        my $e = item_end($C, $T, $j);
        $test[$_] = 1 for $i .. $e - 1;
        $i = $e > $i ? $e : $i + 1;
    }
    return (\@test, \@paths);
}
# Every #[path] value in the file, test-only or not (used inside test files only).
sub all_paths {
    my ($C, $T) = @_;
    my @paths;
    for (my $i = 0; $i < @$C; $i++) {
        my ($end, $compact, $lit) = attribute_at($C, $T, $i);
        next unless defined $end;
        my $p = path_of($compact, $lit);
        push @paths, $p if defined $p;
    }
    return @paths;
}
# ([line, code] of every non-test line, test-only #[path] values)
sub non_test_lines {
    my ($L, $C, $T) = lex($_[0]);
    my ($test, $paths) = regions($C, $T);
    my %by;
    for my $k (0 .. $#$C) { $by{$L->[$k]} .= $C->[$k] unless $test->[$k]; }
    my @out;
    for my $ln (sort { $a <=> $b } keys %by) {
        (my $s = $by{$ln}) =~ s/^\s+|\s+$//g;
        push @out, [$ln, $s] if length $s;
    }
    return (\@out, $paths);
}

1;
