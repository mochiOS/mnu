#!/usr/bin/env perl
use strict;
use warnings;

my $file = shift @ARGV // "changelog";

open my $fh, "<", $file or die "cannot open $file: $!\n";
my @lines = <$fh>;
close $fh;

chomp @lines;

my @errors;
my $max_line_length = 60;

sub error {
    my ($line_no, $message) = @_;
    push @errors, "line $line_no: $message";
}

sub get_line {
    my ($index) = @_;
    return defined $lines[$index] ? $lines[$index] : "";
}

for my $i (0 .. $#lines) {
    my $line_no = $i + 1;
    my $line = $lines[$i];

    if (length($line) > $max_line_length) {
        error($line_no, "line too long. max $max_line_length characters");
    }
}

if (get_line(0) !~ /^the mnu kernel ChangeLog\s+- version \d+\.\d+(?:\.\d+)?(?:-[A-Za-z0-9._-]+)?$/) {
    error(1, "invalid header. expected: the mnu kernel ChangeLog   - version X.Y[-suffix]");
}

if (get_line(1) !~ /^    - Release date: \d{4}-\d{2}-\d{2}$/) {
    error(2, "invalid release date. expected YYYY-MM-DD");
}

if (get_line(2) !~ /^    - Release creator: [A-Za-z0-9._-]+$/) {
    error(3, "invalid release creator");
}

if (get_line(3) ne "") {
    error(4, "expected blank line");
}

if (get_line(4) ne "Changes:") {
    error(5, "expected: Changes:");
}

my $has_change = 0;
my $current_item = 0;

for my $i (5 .. $#lines) {
    my $line = $lines[$i];
    my $line_no = $i + 1;

    if ($line =~ /^\* .+/) {
        $has_change = 1;
        $current_item = 1;
        next;
    }

    if ($line =~ /^  .+/) {
        if (!defined $current_item) {
            error($line_no, "continuation line appears before any change item");
        }
        next;
    }

    if ($line eq "") {
        next;
    }

    error($line_no, "invalid change line. expected '* ' or two-space continuation");
}

if (!defined $has_change) {
    error(6, "at least one change item is required");
}

if (@errors) {
    print "ChangeLog format check failed:\n";
    for my $error (@errors) {
        print "- $error\n";
    }
    exit 1;
}

print "ChangeLog format check passed.\n";
exit 0;