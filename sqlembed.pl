#!/usr/bin/perl
print "static char * sql_embeded_init[] = {\n";
while (<STDIN>) {
    chomp;
    s/^\s+//;
    s/\s+$//;
    s/"/\\"/g;
    print "\t\"$_\",\n";
}
print "NULL\n};\n";
