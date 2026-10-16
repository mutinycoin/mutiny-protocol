#!/usr/bin/env perl
# Package whole-tree identity, including added/removed files, directories and links.
use strict; use warnings;
use Cwd qw(abs_path); use File::Find; use Digest::SHA qw(sha256_hex);
my ($mode,$root)=@ARGV; die "usage: package-tree.pl snapshot|manifest ROOT\n" unless defined($root) && $mode =~ /^(snapshot|manifest)$/;
$root=abs_path($root) // die "missing root\n";
my @paths;
find({no_chdir=>1,wanted=>sub { push @paths,$File::Find::name unless $File::Find::name eq $root; }},$root);
my %expected;
if ($mode eq 'manifest') {
    open my $mf,'<',"$root/PACKAGE-MANIFEST.sha256" or die "manifest missing\n";
    while (<$mf>) { chomp; s/\r$//; /\A([a-f0-9]{64}) [ *](?:\.\/)?(.+)\z/ or die "invalid manifest entry\n";
        my($h,$p)=($1,$2); die "unsafe/duplicate manifest path: $p\n" if $p =~ m{(?:^/|\\|(?:^|/)\.\.(?:/|$))} || exists $expected{$p};
        $expected{$p}=$h;
    }
}
my $bad=0;
for my $path (sort @paths) {
    my $p=substr($path,length($root)+1); die "unrepresentable package name\n" if $p =~ /[\r\n]/;
    if (-l $path) { if($mode eq 'manifest'){print "FAIL  $p: package symlink is not a manifest-listed regular file\n";$bad++} else {print 'L ',sha256_hex(readlink $path),"  $p\n"} }
    elsif (-d $path) {print "D -  $p\n" if $mode eq 'snapshot'}
    elsif (-f $path) {
        open my $f,'<:raw',$path or die "cannot read $p: $!\n"; my $sha=Digest::SHA->new(256)->addfile($f)->hexdigest;
        if($mode eq 'snapshot'){print "F $sha  $p\n"}
        elsif($p eq 'PACKAGE-MANIFEST.sha256') { next }
        elsif(!exists $expected{$p}){print "FAIL  $p: unlisted package file\n";$bad++}
        elsif(delete($expected{$p}) ne $sha){print "FAIL  $p: package manifest hash mismatch\n";$bad++}
    } else {die "special object in package: $p\n"}
}
if($mode eq 'manifest') {
 for my $p(sort keys %expected){print "FAIL  $p: manifest file missing\n";$bad++}
 print "PASS  package manifest covers every regular file; no additions/removals\n" unless $bad;
 exit($bad ? 1 : 0);
}
