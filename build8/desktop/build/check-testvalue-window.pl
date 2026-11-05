#!/usr/bin/env perl
# W15 source/configuration tripwire. Feature reachability is independently checked by Cargo tree.
use strict; use warnings; use File::Find; use File::Spec; use FindBin;
require "$FindBin::Bin/rust-source-model.pl";
my $root = shift // '.'; my $failed=0;
sub read_file { my ($path)=@_; open my $f,'<',"$root/$path" or die "$path: $!"; local $/; my $s=<$f>; $s =~ s/\r//g; return $s; }
sub check($$) { die "W15 checker internal argument error" unless @_ == 2; my ($ok,$why)=@_; print(($ok?'PASS':'FAIL')," W15 $why\n"); $failed++ unless $ok;}
sub shipping_text {
    my ($path)=@_;my ($lines,$chars,$literal)=RustSourceModel::lex(read_file($path));
    my ($test)=RustSourceModel::regions($chars,$literal);
    return join('',map {$test->[$_]?' ':$chars->[$_]} 0..$#$chars);
}
# Frozen V1/V2 ceremony stores remain historical test source. Current normal callers must
# enter the identified, issued-challenge V3 store; retaining old files is not reachability.
my $consensus=shipping_text('consensus/src/lib.rs');
check($consensus =~ /pub\s+mod\s+treasury_rehearsal_v3\s*;/
    && $consensus =~ /pub\s+mod\s+treasury_admission_v3\s*;/
    && $consensus !~ /treasury_(?:rehearsal|admission)_v[12]\b/,
    'normal Treasury module graph exports only identified V3 ceremony');
for my $tree(qw(desktop/src wallet-core/src)) {
    find({no_chdir=>1,wanted=>sub {return unless /\.rs$/ && -f $_;
        my $rel=File::Spec->abs2rel($_,$root);$rel =~ s{\\}{/}g;
        check(shipping_text($rel) !~ /treasury_(?:rehearsal|admission)_v[12]\b/,
            "current Treasury import graph $rel");
    }},"$root/$tree");
}
# Real authenticated NODE fixtures live in wallet-core tests. This exact dev-only edge must
# never become a shipping dependency or forward validator features/custody from NODE.
my $core=read_file('wallet-core/Cargo.toml'); my $table=''; my @node_edges;
for my $line(split /\n/,$core){$table=$line if $line =~ /^\[/; push @node_edges,[$table,$line] if $line =~ /^mutinyd-v8\s*=/;}
check(@node_edges==1 && $node_edges[0][0] eq '[dev-dependencies]'
    && $node_edges[0][1] eq 'mutinyd-v8 = { path = "../node", default-features = false }',
    'NODE fixture edge is exact dev-only with defaults disabled');
# The controlled voter clock is a separate nondefault TEST fixture. It may be
# forwarded only by this exact NODE dev edge, never a normal/build/target edge.
my ($timer_declaration,$timer_dev)=(0,0);
find({no_chdir=>1,wanted=>sub {
    return unless /Cargo\.toml$/ && -f $_;
    my $rel=File::Spec->abs2rel($_,$root); $rel =~ s{\\}{/}g;
    return if $rel =~ m{(?:^|/)(?:target|vendor|qualification)/};
    my $table='';
    for my $line(split /\n/,read_file($rel)) {
        $line =~ s/\s*#.*$//; next if $line =~ /^\s*$/;
        $table=$line if $line =~ /^\[/;
        next unless $line =~ /actor-timer-test-fixtures/;
        if($rel eq 'consensus/Cargo.toml' && $table eq '[features]'
            && $line eq 'actor-timer-test-fixtures = []') { $timer_declaration++; }
        elsif($rel eq 'node/Cargo.toml' && $table eq '[dev-dependencies]'
            && $line eq 'mutiny-consensus-v8 = { path = "../consensus", features = ["actor-timer-test-fixtures"] }') { $timer_dev++; }
        else { check(0,"actor timer fixture excluded from shipping manifest $rel"); }
    }
}},$root);
check($timer_declaration==1 && $timer_dev==1,'actor timer has exact nondefault declaration and NODE dev-only edge');
my $manifest=read_file('desktop/Cargo.toml');
my @features=$manifest =~ /^\[features\]\n(.*?)(?=^\[|\z)/msg;
check(@features==1 && $features[0] =~ /^testvalue-window = \["mutiny-wallet-core-v8\/test-value-signing"\]$/m
    && $features[0] !~ /^(?!#|testvalue-window\b|\s*$)\S/m,'feature has one exact forward and no default');
my @bins=$manifest =~ /^\[\[bin\]\]\n(.*?)(?=^\[|\z)/msg;
my %expected=('mutiny-wallet-v8'=>'src/main.rs','mutiny-wallet-v8-testvalue'=>'src/testvalue/main.rs','mutiny-treasury-v8-testvalue'=>'src/testvalue/treasury_main.rs');
check(@bins==3,'exact three explicit executable targets');
for my $bin(@bins){my($name)=$bin=~/^name = "([^"]+)"$/m;my($path)=$bin=~/^path = "([^"]+)"$/m;
    check(defined($name)&&exists($expected{$name})&&defined($path)&&$path eq $expected{$name},'target identity/path');
    next unless defined($name)&&exists($expected{$name}); delete $expected{$name};
    check($name eq 'mutiny-wallet-v8' ? $bin !~ /required-features/ : $bin =~ /^required-features = \["testvalue-window"\]$/m,'test executables require explicit feature');
}
my %sites=('desktop/src/main.rs'=>1,'desktop/src/wallet_v2.rs'=>1,'desktop/src/wallet_controller_v2.rs'=>3,
    'desktop/src/testvalue/main.rs'=>1,'desktop/src/testvalue/treasury_main.rs'=>1);
find({no_chdir=>1,wanted=>sub { return unless /\.rs$/ && -f $_;
    my $rel=File::Spec->abs2rel($_,$root); $rel =~ s{\\}{/}g;
    my $s=read_file($rel);my $count=()=$s=~/feature\s*=\s*"testvalue-window"/g;
    check($count==($sites{$rel}//0),"feature source-site count $rel") if $count || exists $sites{$rel};
    # Ordinary literals and #[path] values remain visible. Only conservatively identified
    # cfg(test) items are masked, so a TEST-only guard can name excluded roots without
    # making those roots reachable from the ordinary executable.
    if($rel !~ m{^desktop/src/testvalue/}){check(shipping_text($rel) !~ /(?:mod\s+testvalue\b|testvalue\/|TESTVALUE-WINDOW-V1)/,"shipping module exclusion $rel");}
}},"$root/desktop/src");
my $main=read_file('desktop/src/main.rs');
check($main =~ /^const TEST_VALUE_WINDOW: bool = cfg!\(feature = "testvalue-window"\);$/m
    && $main =~ /^const _: \(\) = assert!\(\s*!TEST_VALUE_WINDOW,/m,'shipping executable rejects feature in every profile');
for my $path(qw(package/windows-wallet-test/run-windows-wallet-tests.sh package/linux-native-test/run-linux-native-tests.sh)){
    my $s=read_file($path);check($s !~ /testvalue-window|mutiny-(?:wallet|treasury)-v8-testvalue/,'shipping runner excludes rehearsal targets');
}
exit($failed?1:0);
