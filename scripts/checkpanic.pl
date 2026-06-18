#!/usr/bin/env perl

use strict;
use warnings;

use Cwd qw(abs_path);
use File::Find;
use File::Spec;

my $root = `git rev-parse --show-toplevel 2>/dev/null`;
chomp $root;

if ($root eq "") {
    die "error: Git project root was not found\n";
}

$root = abs_path($root);

my $src_dir = File::Spec->catdir($root, "src");
my $allowed_file = abs_path(
    File::Spec->catfile($src_dir, "panic.rs")
);

if (!-d $src_dir) {
    die "error: src directory was not found: $src_dir\n";
}

my @errors;

find(
    {
        no_chdir => 1,

        wanted   => sub {
            my $path = $File::Find::name;

            return unless -f $path;
            return unless $path =~ /\.rs\z/;

            my $absolute_path = abs_path($path);

            if (defined $allowed_file &&
                $absolute_path eq $allowed_file) {
                return;
            }

            open my $fh, "<", $path
                or die "error: cannot open $path: $!\n";

            my $line_no = 0;
            my $in_block_comment = 0;

            while (my $line = <$fh>) {
                $line_no++;

                my $code = strip_comments(
                    $line,
                    \$in_block_comment
                );

                if ($code =~ /\bpanic\s*!/) {
                    my $relative_path =
                        File::Spec->abs2rel($path, $root);

                    push @errors,
                        "$relative_path:$line_no: "
                            . "panic! is only allowed in src/panic.rs";
                }
            }

            close $fh;
        },
    },
    $src_dir
);

if (@errors) {
    print STDERR "panic usage check failed:\n";

    for my $error (@errors) {
        print STDERR "- $error\n";
    }

    exit 1;
}

print "panic usage check passed.\n";
exit 0;

sub strip_comments {
    my ($line, $in_block_comment_ref) = @_;

    my $result = "";
    my $index = 0;
    my $length = length($line);
    my $in_string = 0;
    my $in_char = 0;
    my $escaped = 0;

    while ($index < $length) {
        my $current = substr($line, $index, 1);
        my $next =
            $index + 1 < $length
                ? substr($line, $index + 1, 1)
                : "";

        if (defined $$in_block_comment_ref) {
            if ($current eq "*" && $next eq "/") {
                $$in_block_comment_ref = 0;
                $index += 2;
                next;
            }

            $index++;
            next;
        }

        if (defined $in_string) {
            $result .= $current;

            if (defined $escaped) {
                $escaped = 0;
            }
            elsif ($current eq "\\") {
                $escaped = 1;
            }
            elsif ($current eq '"') {
                $in_string = 0;
            }

            $index++;
            next;
        }

        if (defined $in_char) {
            $result .= $current;

            if (defined $escaped) {
                $escaped = 0;
            }
            elsif ($current eq "\\") {
                $escaped = 1;
            }
            elsif ($current eq "'") {
                $in_char = 0;
            }

            $index++;
            next;
        }

        if ($current eq "/" && $next eq "/") {
            last;
        }

        if ($current eq "/" && $next eq "*") {
            $$in_block_comment_ref = 1;
            $index += 2;
            next;
        }

        if ($current eq '"') {
            $in_string = 1;
        }
        elsif ($current eq "'") {
            $in_char = 1;
        }

        $result .= $current;
        $index++;
    }

    return $result;
}