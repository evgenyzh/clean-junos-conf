#!/usr/bin/perl

use strict;
use warnings;

# Clean JunOS config with support for as-path, community, group structures, and active/inactive handling
# Author: Pavel Gulchouck <gul@gul.kiev.ua>, Updated by evgenyzh
# Version 2.17
# Date: 06.05.2025
# Free software

my $debug = 0;
my $exclude_inactive = 0;     # Option to exclude inactive entities
my $graph_output = 0;         # Option to output dependency graph in DOT format
my $report_dependencies = 0;  # Option to output dependency report
my $deletion_report = 0;      # Option to output deletion report
my @common_files;             # Array to store common configuration files

# Process command-line arguments
while ($ARGV[0] =~ /^-/) {
    if ($ARGV[0] eq "-v") {
        $debug++;
    } elsif ($ARGV[0] eq "-c") {
        shift;
        push @common_files, $ARGV[0] if -f $ARGV[0];
    } elsif ($ARGV[0] eq "-ni") {
        $exclude_inactive = 1;
    } elsif ($ARGV[0] eq "-g") {
        $graph_output = 1;
    } elsif ($ARGV[0] eq "-r") {
        $report_dependencies = 1;
    } elsif ($ARGV[0] eq "-dr") {
        $deletion_report = 1;
    } elsif ($ARGV[0] eq "-h") {
        print_help();
        exit(0);
    } else {
        warn "Unknown switch '$ARGV[0]' ignored\n";
    }
    shift;
}

# Validate input
if ($ARGV[0]) {
    my %entities;
    parse_config(\@common_files, \%entities, 1);  # Parse common files (is_common => 1)
    parse_config([$ARGV[0]], \%entities, 0);      # Parse main config
    cleanup_entities(\%entities);
    print_dependency_report(\%entities) if $report_dependencies;
    print_dependency_graph(\%entities) if $graph_output;
} else {
    die "No configuration file specified. Use -h for help.\n";
}

sub print_help {
    print <<'HELP';
Clean JunOS config, remove unused tokens with group structure and inactive handling
  Usage:
    cleanconf [<options>] <config>
  Options:
    -v   - Increase verbose level for debugging
    -c   - Specify a common configuration file (can be used multiple times)
    -ni  - Exclude inactive entities from processing and output
    -g   - Output dependency graph in DOT format
    -r   - Output dependency report in tabular format
    -dr  - Output deletion report
    -h   - Print this help and exit
  Examples:
    cleanconf -v config.txt
    cleanconf -c common.txt -ni config.txt
    cleanconf -g config.txt > graph.dot
    cleanconf -r config.txt
HELP
}

sub debug {
    my ($level, $message) = @_;
    return if $debug < $level;
    print STDERR "DEBUG: $message\n";
}

sub parse_config {
    my ($files, $entities_ref, $is_common) = @_;
    $is_common //= 0;

    foreach my $file (@$files) {
        open my $fh, '<', $file or die "Cannot open file '$file': $!\n";
        my $linenum = 0;

        while (my $line = <$fh>) {
            $linenum++;
            chomp $line;

            # Check for inactive status
            my $is_inactive = $line =~ /inactive:\s+/;

            # Parse group structures
            if ($line =~ /^\s*(?:inactive:\s+)?group\s+(\S+)\s+\{\s*$/) {
                my $name = $1;
                my $key = "group:$name";
                my $lines = '';
                my $active_neighbors = 0;
                my $brace_level = 1;

                debug(1, "Parsing group $name in $file, inactive: " . ($is_inactive ? "yes" : "no"));

                while (my $group_line = <$fh>) {
                    $linenum++;
                    chomp $group_line;
                    $lines .= $group_line . "\n";

                    $brace_level++ if $group_line =~ /\{\s*$/;
                    $brace_level-- if $group_line =~ /^\s*\}\s*$/;
                    last if $brace_level == 0;

                    # Count active neighbors only if group is not inactive and neighbor is not inactive
                    if ($group_line =~ /^\s*neighbor\s+\S+\s*(?:;|\{)/ && !$is_inactive && $group_line !~ /inactive:/) {
                        $active_neighbors++;
                        debug(1, "Found active neighbor in group $name: $group_line");
                    }

                    # Track dependencies for import/export policies
                    if ($group_line =~ /^\s*(?:import|export)\s+(\[.*?\]|\(.*?\));/) {
                        my $policy_str = $1;
                        my %unique_policies;
                        $policy_str =~ s/[\[\]\(\)]//g;  # Remove brackets and parentheses
                        $policy_str =~ s/\|\||&&//g;     # Remove logical operators
                        my @policies = grep { /^\w[\w-]*$/ } split(/\s+/, $policy_str);
                        foreach my $policy (@policies) {
                            next if $unique_policies{$policy}++;  # Skip duplicates
                            push @{$entities_ref->{$key}{references}}, "policy-statement:$policy";
                            $entities_ref->{"policy-statement:$policy"}{referenced_by} ||= [];
                            push @{$entities_ref->{"policy-statement:$policy"}{referenced_by}}, $key;
                            debug(2, "Dependency: group $name references policy-statement $policy");
                        }
                    }
                }

                if ($brace_level != 0) {
                    warn "Warning: Unclosed group $name in $file at line $linenum\n";
                }

                $entities_ref->{$key} = {
                    type => 'group',
                    name => $name,
                    is_inactive => $is_inactive,
                    is_common => $is_common,
                    active_neighbors => $active_neighbors,
                    references => $entities_ref->{$key}{references} // [],
                    referenced_by => $entities_ref->{$key}{referenced_by} // [],
                    lines => $lines
                };
                debug(1, "Group $name has $active_neighbors active neighbors, inactive: " . ($is_inactive ? "yes" : "no"));
            }

            # Parse multi-line entities
            for my $entity_type (qw(prefix-list policy-statement filter policer)) {
                if ($line =~ /^\s*(?:inactive:\s+)?$entity_type\s+(\S+)\s+\{\s*$/) {
                    my $name = $1;
                    my $key = "$entity_type:$name";
                    my $brace_level = 1;
                    my $lines = '';

                    while (my $entity_line = <$fh>) {
                        $linenum++;
                        chomp $entity_line;
                        $lines .= $entity_line . "\n";

                        $brace_level++ if $entity_line =~ /\{\s*$/;
                        $brace_level-- if $entity_line =~ /^\s*\}\s*$/;
                        last if $brace_level == 0;

                        # Track dependencies for policy-statement
                        if ($entity_type eq 'policy-statement') {
                            if ($entity_line =~ /^\s*from\s+prefix-list\s+(\S+)/) {
                                my $prefix_list = $1;
                                $prefix_list =~ s/;$//;  # Remove trailing semicolon
                                push @{$entities_ref->{$key}{references}}, "prefix-list:$prefix_list";
                                $entities_ref->{"prefix-list:$prefix_list"}{referenced_by} ||= [];
                                push @{$entities_ref->{"prefix-list:$prefix_list"}{referenced_by}}, $key;
                                debug(2, "Dependency: policy-statement $name references prefix-list $prefix_list");
                            }
                            if ($entity_line =~ /^\s*from\s+community\s+(\S+)/) {
                                my $community = $1;
                                $community =~ s/;$//;  # Remove trailing semicolon
                                # Skip community arrays like [ 43274:3301 43274:1000 ]
                                next if $community =~ /^\[.*\]$/;
                                push @{$entities_ref->{$key}{references}}, "community:$community";
                                $entities_ref->{"community:$community"}{referenced_by} ||= [];
                                push @{$entities_ref->{"community:$community"}{referenced_by}}, $key;
                                debug(2, "Dependency: policy-statement $name references community $community");
                            }
                            if ($entity_line =~ /^\s*from\s+as-path\s+(\S+)/) {
                                my $as_path = $1;
                                $as_path =~ s/;$//;  # Remove trailing semicolon
                                push @{$entities_ref->{$key}{references}}, "as-path:$as_path";
                                $entities_ref->{"as-path:$as_path"}{referenced_by} ||= [];
                                push @{$entities_ref->{"as-path:$as_path"}{referenced_by}}, $key;
                                debug(2, "Dependency: policy-statement $name references as-path $as_path");
                            }
                            if ($entity_line =~ /^\s*then\s+policy\s+(\S+)/) {
                                my $policy = $1;
                                $policy =~ s/;$//;  # Remove trailing semicolon
                                push @{$entities_ref->{$key}{references}}, "policy-statement:$policy";
                                $entities_ref->{"policy-statement:$policy"}{referenced_by} ||= [];
                                push @{$entities_ref->{"policy-statement:$policy"}{referenced_by}}, $key;
                                debug(2, "Dependency: policy-statement $name references policy-statement $policy");
                            }
                        }
                        if ($entity_type eq 'filter' && $entity_line =~ /^\s*policer\s+(\S+)/) {
                            my $policer = $1;
                            $policer =~ s/;$//;  # Remove trailing semicolon
                            push @{$entities_ref->{$key}{references}}, "policer:$policer";
                            $entities_ref->{"policer:$policer"}{referenced_by} ||= [];
                            push @{$entities_ref->{"policer:$policer"}{referenced_by}}, $key;
                            debug(2, "Dependency: filter $name references policer $policer");
                        }
                    }

                    if ($brace_level != 0) {
                        warn "Warning: Unclosed $entity_type $name in $file at line $linenum\n";
                    }

                    $entities_ref->{$key} = {
                        type => $entity_type,
                        name => $name,
                        is_inactive => $is_inactive,
                        is_common => $is_common,
                        references => $entities_ref->{$key}{references} // [],
                        referenced_by => $entities_ref->{$key}{referenced_by} // [],
                        lines => $lines
                    };
                }
            }

            # Parse single-line entities
            for my $entity_type (qw(as-path community)) {
                if ($line =~ /^\s*(?:inactive:\s+)?$entity_type\s+(\S+)\s+(.*);\s*$/) {
                    my $name = $1;
                    # Skip arrays like [ 43274:3301 43274:1000 ]
                    next if $name =~ /^\[.*\]$/;
                    my $key = "$entity_type:$name";
                    $entities_ref->{$key} = {
                        type => $entity_type,
                        name => $name,
                        is_inactive => $is_inactive,
                        is_common => $is_common,
                        references => [],
                        referenced_by => [],
                        lines => $line
                    };
                }
            }
        }

        close $fh;
    }

    # No longer need separate referenced_by update loop since we update it inline
}

sub cleanup_entities {
    my ($entities_ref) = @_;
    my %deleted_entities;

    # Two-pass cleanup
    for my $pass (1..2) {
        debug(1, "Cleanup pass $pass");
        foreach my $key (sort keys %$entities_ref) {
            my $entity = $entities_ref->{$key};
            my ($type, $name) = ($entity->{type}, $entity->{name});

            # Skip common entities
            next if $entity->{is_common};

            # Skip inactive entities if -ni is set
            next if $exclude_inactive && $entity->{is_inactive};

            # Determine deletability
            my $is_deletable = $type eq 'group' ? $entity->{active_neighbors} == 0 : 1;

            # Check references (exclude references from deleted entities)
            my @active_refs = grep { !exists $deleted_entities{$_} } @{$entity->{referenced_by}};
            my $is_referenced = @active_refs > 0;

            # Debug why entity is not deleted
            debug(2, "$type $name: deletable=$is_deletable, referenced=$is_referenced, inactive=$entity->{is_inactive}, pass=$pass");

            # Delete inactive entities in pass 1, active but deletable entities in pass 2
            if ($is_deletable && !$is_referenced && ($pass == 2 || ($pass == 1 && $entity->{is_inactive}))) {
                if ($deletion_report) {
                    print "# Proposed deletion: $type $name\n";
                    print "# Dependencies:\n";
                    print "#   Referenced by: None\n";
                    print "#   References: ", join(", ", @{$entity->{references}}) || "None", "\n";
                }

                # Map type to delete path
                my $delete_path = $type eq 'prefix-list' ? 'policy-options prefix-list' :
                                  $type eq 'policy-statement' ? 'policy-options policy-statement' :
                                  $type eq 'as-path' ? 'policy-options as-path' :
                                  $type eq 'community' ? 'policy-options community' :
                                  $type eq 'filter' ? 'firewall filter' :
                                  $type eq 'policer' ? 'firewall policer' :
                                  $type;  # group
                print "delete $delete_path $name\n";

                $deleted_entities{$key} = 1;
                delete $entities_ref->{$key};
                debug(1, "$type $name deleted");
            } elsif ($is_referenced) {
                debug(1, "$type $name skipped: referenced by " . join(", ", @active_refs));
            } elsif (!$is_deletable) {
                debug(1, "$type $name skipped: " . ($type eq 'group' ? "has $entity->{active_neighbors} active neighbors" : "not deletable"));
            }
        }
    }
}

sub print_dependency_report {
    my ($entities_ref) = @_;

    # Define type abbreviations
    my %type_abbreviations = (
        'policy-statement' => 'PS',
        'group' => 'G',
        'prefix-list' => 'PL',
        'community' => 'CM',
        'as-path' => 'AP',
        'filter' => 'F'
    );

    # Get terminal width using tput cols
    my $term_width = `tput cols 2>/dev/null` || 120;
    chomp $term_width;
    $term_width = 120 if !$term_width || $term_width < 120;  # Ensure minimum width

    print "\n=== Dependency Report ===\n\n";

    # Define maximum column widths
    my %max_widths = (
        entity => 30,
        type => 15,
        status => 12,
        referenced_by => 40,
        references => 40
    );

    # Ensure total width fits within terminal (accounting for borders and padding)
    my $total_max_width = $max_widths{entity} + $max_widths{type} + $max_widths{status} +
                         $max_widths{referenced_by} + $max_widths{references} + 11;  # Borders and padding
    if ($total_max_width > $term_width) {
        # Scale down widths proportionally
        my $scale = ($term_width - 11) / ($total_max_width - 11);
        $max_widths{entity} = int($max_widths{entity} * $scale) || 15;
        $max_widths{type} = int($max_widths{type} * $scale) || 10;
        $max_widths{status} = int($max_widths{status} * $scale) || 8;
        $max_widths{referenced_by} = int($max_widths{referenced_by} * $scale) || 20;
        $max_widths{references} = int($max_widths{references} * $scale) || 20;
    }

    # Collect data for table
    my @rows;
    foreach my $key (sort keys %$entities_ref) {
        my $entity = $entities_ref->{$key};
        my @status_parts;
        push @status_parts, 'inactive' if $entity->{is_inactive};
        push @status_parts, 'common' if $entity->{is_common};
        my $status = @status_parts ? join(", ", @status_parts) : 'active';

        # Remove duplicates from referenced_by
        my %unique_referenced_by;
        my @unique_referenced_by = grep { !$unique_referenced_by{$_}++ } @{$entity->{referenced_by}};

        # Format type, referenced_by, and references with abbreviations
        my $type_str = $type_abbreviations{$entity->{type}} || $entity->{type};
        my @ref_by_abbr = map { s/^(.*?):/$type_abbreviations{$1} ? "$type_abbreviations{$1}:" : "$1:"/e; $_ } @unique_referenced_by;
        my @ref_abbr = map { s/^(.*?):/$type_abbreviations{$1} ? "$type_abbreviations{$1}:" : "$1:"/e; $_ } @{$entity->{references}};

        # Format referenced_by and references as multi-line strings
        my $referenced_by_str = @ref_by_abbr ? join("\n", @ref_by_abbr) : "None";
        my $references_str = @ref_abbr ? join("\n", @ref_abbr) : "None";

        push @rows, {
            entity => $entity->{name},
            type => $type_str,
            status => $status,
            referenced_by => $referenced_by_str,
            references => $references_str,
            max_lines => 1 + (scalar(@ref_by_abbr) > scalar(@ref_abbr) ? scalar(@ref_by_abbr) : scalar(@ref_abbr))
        };
    }

    # Calculate actual column widths based on content
    my %widths = (
        entity => length("Entity"),
        type => length("Type"),
        status => length("Status"),
        referenced_by => length("Referenced by"),
        references => length("References")
    );

    foreach my $row (@rows) {
        my $entity_len = length($row->{entity});
        $entity_len = $max_widths{entity} if $entity_len > $max_widths{entity};  # Cap at max_widths
        $widths{entity} = $entity_len if $entity_len > $widths{entity} && $entity_len <= $max_widths{entity};

        my $type_len = length($row->{type});
        $type_len = $max_widths{type} if $type_len > $max_widths{type};
        $widths{type} = $type_len if $type_len > $widths{type} && $type_len <= $max_widths{type};

        my $status_len = length($row->{status});
        $status_len = $max_widths{status} if $status_len > $max_widths{status};
        $widths{status} = $status_len if $status_len > $widths{status} && $status_len <= $max_widths{status};

        my @ref_by_lines = split(/\n/, $row->{referenced_by});
        my @ref_lines = split(/\n/, $row->{references});
        foreach my $line (@ref_by_lines) {
            my $len = defined($line) ? length($line) : 0;
            $len = $max_widths{referenced_by} if $len > $max_widths{referenced_by};
            $widths{referenced_by} = $len if $len > $widths{referenced_by} && $len <= $max_widths{referenced_by};
        }
        foreach my $line (@ref_lines) {
            my $len = defined($line) ? length($line) : 0;
            $len = $max_widths{references} if $len > $max_widths{references};
            $widths{references} = $len if $len > $widths{references} && $len <= $max_widths{references};
        }
    }

    # Print table
    my $header = sprintf("| %-${widths{entity}}s | %-${widths{type}}s | %-${widths{status}}s | %-${widths{referenced_by}}s | %-${widths{references}}s |",
                         "Entity", "Type", "Status", "Referenced by", "References");
    my $separator = '+' . ('-' x ($widths{entity} + 2)) . '+' . ('-' x ($widths{type} + 2)) . '+' .
                    ('-' x ($widths{status} + 2)) . '+' . ('-' x ($widths{referenced_by} + 2)) . '+' .
                    ('-' x ($widths{references} + 2)) . '+';

    print "$separator\n$header\n$separator\n";

    foreach my $row (@rows) {
        my @ref_by_lines = split(/\n/, $row->{referenced_by});
        my @ref_lines = split(/\n/, $row->{references});
        my $max_lines = $row->{max_lines};

        for my $i (0 .. $max_lines - 1) {
            my $entity_str = $i == 0 ? substr($row->{entity}, 0, $max_widths{entity} - 3) : "";
            $entity_str .= "..." if defined($row->{entity}) && length($row->{entity}) > $max_widths{entity} - 3 && $i == 0;
            my $type_str = $i == 0 ? substr($row->{type}, 0, $max_widths{type} - 3) : "";
            $type_str .= "..." if defined($row->{type}) && length($row->{type}) > $max_widths{type} - 3 && $i == 0;
            my $status_str = $i == 0 ? substr($row->{status}, 0, $max_widths{status} - 3) : "";
            $status_str .= "..." if defined($row->{status}) && length($row->{status}) > $max_widths{status} - 3 && $i == 0;
            my $ref_by_str = $ref_by_lines[$i] ? substr($ref_by_lines[$i], 0, $max_widths{referenced_by} - 3) : "";
            $ref_by_str .= "..." if defined($ref_by_lines[$i]) && length($ref_by_lines[$i]) > $max_widths{referenced_by} - 3;
            my $ref_str = $ref_lines[$i] ? substr($ref_lines[$i], 0, $max_widths{references} - 3) : "";
            $ref_str .= "..." if defined($ref_lines[$i]) && length($ref_lines[$i]) > $max_widths{references} - 3;

            printf "| %-${widths{entity}}s | %-${widths{type}}s | %-${widths{status}}s | %-${widths{referenced_by}}s | %-${widths{references}}s |\n",
                   $entity_str, $type_str, $status_str, $ref_by_str, $ref_str;
        }
        print $separator . "\n";
    }

    # Print abbreviations legend
    print "\nAbbreviations:\n";
    print "PS - policy-statement, G - group, PL - prefix-list, CM - community, AP - as-path, F - filter\n\n";
}

sub print_dependency_graph {
    my ($entities_ref) = @_;

    # Define type abbreviations
    my %type_abbreviations = (
        'policy-statement' => 'PS',
        'group' => 'G',
        'prefix-list' => 'PL',
        'community' => 'CM',
        'as-path' => 'AP',
        'filter' => 'F'
    );

    print "digraph JunOS_Dependencies {\n";
    print "// Abbreviations: PS - policy-statement, G - group, PL - prefix-list, CM - community, AP - as-path, F - filter\n\n";

    # Collect all referenced entities (even if not in %entities_ref)
    my %all_nodes;
    foreach my $key (keys %$entities_ref) {
        $all_nodes{$key} = 1;
        foreach my $ref_key (@{$entities_ref->{$key}{references}}) {
            $all_nodes{$ref_key} = 1;
        }
    }

    # Print nodes
    foreach my $key (sort keys %all_nodes) {
        my ($type, $name) = split(/:/, $key, 2);
        my $abbr_type = $type_abbreviations{$type} || $type;
        my $node_label = "$abbr_type:$name";
        my @attributes;
        if (exists $entities_ref->{$key}) {
            push @attributes, 'style=dashed' if $entities_ref->{$key}{is_inactive};
            push @attributes, 'color=blue' if $entities_ref->{$key}{is_common};
        } else {
            push @attributes, 'color=red', 'label="MISSING: ' . $node_label . '"';
        }
        my $attr_str = @attributes ? " [" . join(",", @attributes) . "]" : "";
        print "  \"$node_label\"$attr_str;\n";
    }

    # Print edges
    foreach my $key (keys %$entities_ref) {
        my ($type, $name) = split(/:/, $key, 2);
        my $abbr_type = $type_abbreviations{$type} || $type;
        my $from_node = "$abbr_type:$name";
        foreach my $ref_key (@{$entities_ref->{$key}{references}}) {
            my ($ref_type, $ref_name) = split(/:/, $ref_key, 2);
            my $abbr_ref_type = $type_abbreviations{$ref_type} || $ref_type;
            my $to_node = "$abbr_ref_type:$ref_name";
            print "  \"$from_node\" -> \"$to_node\";\n";
        }
    }

    print "}\n";
}
