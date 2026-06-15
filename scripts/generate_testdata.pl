#!/usr/bin/env perl

use strict;
use warnings;

my $out_dir = "./examples/fs";
my $out_file = "$out_dir/testdata";
my $size = 8 * 1024 * 1024;
my $chunk_size = 1024 * 1024;

if (!-d $out_dir) {
    mkdir $out_dir or die "failed to create $out_dir: $!\n";
}

if (-e $out_file) {
    if (-s $out_file == $size) {
        print "test data already exists: $out_file\n";
        exit 0;
    }
    unlink $out_file or die "failed to remove stale $out_file: $!\n";
}

open(my $fh, ">", $out_file) or die "failed to open $out_file: $!\n";
binmode($fh) or die "failed to set binary mode: $!\n";

print "generating test data...\n";

my $seed = 0xdeadbeef;
my $written = 0;

while ($written < $size) {
    my $remaining = $size - $written;
    my $write_size = $remaining < $chunk_size ? $remaining : $chunk_size;
    my $buf = "";

    for (my $i = 0; $i < $write_size; $i++) {
        $seed ^= ($seed << 13) & 0xffffffff;
        $seed ^= ($seed >> 17);
        $seed ^= ($seed << 5) & 0xffffffff;
        $seed &= 0xffffffff;

        $buf .= chr($seed & 0xff);
    }

    print $fh $buf or die "failed to write $out_file: $!\n";
    $written += $write_size;
}

close($fh) or die "failed to close $out_file: $!\n";

print "generated: $out_file\n";
print "size: $size bytes\n";
