# Clean JunOS Configuration

`clean-junos-conf.pl` is a Perl script designed to clean unused tokens from JunOS configurations and analyze dependencies between entities such as BGP groups, policy statements, communities, prefix lists, AS paths, and filters. It supports active/inactive entities, common configuration files, and generates dependency reports or graphs in DOT format.

## Features
- **Cleanup**: Removes unused entities (e.g., groups with no active neighbors, unreferenced policies) while respecting dependencies.
- **Dependency Report**: Displays a tabular report of entities, their types, status, and dependencies (`Referenced by` and `References`).
- **Dependency Graph**: Outputs a graph in DOT format for visualization with tools like Graphviz.
- **Common Files**: Supports common configuration files (e.g., shared communities) via the `-c` option.
- **Inactive Handling**: Optionally excludes inactive entities with the `-ni` flag.
- **Verbose Mode**: Debug output with `-v` for troubleshooting.

## Installation
1. **Requirements**:
   - Perl 5 (included in most Linux distributions).
   - `tput` (part of `ncurses`, used for terminal width detection).
2. **Download**:
   ```bash
   git clone https://github.com/yourusername/clean-junos-conf.git
   cd clean-junos-conf
   ```
3. **Make executable**:
   ```bash
   chmod +x clean-junos-conf.pl
   ```

## Usage
```bash
./clean-junos-conf.pl [<options>] <config>
```

### Options
- `-v`: Increase verbose level for debugging.
- `-c <file>`: Specify a common configuration file (can be used multiple times).
- `-ni`: Exclude inactive entities from processing and output.
- `-g`: Output dependency graph in DOT format.
- `-r`: Output dependency report in tabular format.
- `-dr`: Output deletion report for removed entities.
- `-h`: Print help and exit.

### Examples
1. **Clean configuration**:
   ```bash
   ./clean-junos-conf.pl examples/example1.conf
   ```
   Outputs `delete` commands for unused entities.

2. **Generate dependency report**:
   ```bash
   ./clean-junos-conf.pl -r examples/example2.conf > output.txt
   ```
   See `examples/example2_output.txt` for sample output.

3. **Generate dependency graph**:
   ```bash
   ./clean-junos-conf.pl -g examples/example1.conf > graph.dot
   dot -Tpng graph.dot -o graph.png
   ```
   See `examples/example1_graph.dot` for sample DOT file.

4. **Use common file and exclude inactive entities**:
   ```bash
   ./clean-junos-conf.pl -c examples/common.conf -ni -r examples/example2.conf
   ```

## Output Formats
### Dependency Report
The report is a table with the following columns:
- **Entity**: Name of the entity (e.g., `Uplinks`, `all-peer-no-advertise`).
- **Type**: Entity type (abbreviated: `PS` for policy-statement, `G` for group, `PL` for prefix-list, `CM` for community, `AP` for as-path, `F` for filter).
- **Status**: `active`, `inactive`, `common`, or combinations (e.g., `inactive, common`).
- **Referenced by**: Entities that reference this one (e.g., `PS:specific-community-to-all-peer`).
- **References**: Entities this one references (e.g., `CM:all-peer-no-advertise`).

**Abbreviations**:
- `PS` - policy-statement
- `G` - group
- `PL` - prefix-list
- `CM` - community
- `AP` - as-path
- `F` - filter

### Dependency Graph
Output in DOT format for visualization with Graphviz:
- Nodes represent entities (e.g., `group:Uplinks`).
- Edges show dependencies (e.g., `group:Uplinks -> policy-statement:ebgp-import-generic`).
- Inactive entities use dashed lines; common entities are blue.

## Examples
The `examples/` directory contains:
- `example1.conf`: Simple BGP group with policies.
- `example2.conf`: Complex configuration with multiple groups, policies, and inactive entities.
- `common.conf`: Common communities used with `-c`.
- `example1_output.txt`, `example2_output.txt`: Sample dependency reports.
- `example1_graph.dot`, `example2_graph.dot`: Sample DOT files.

Try:
```bash
./clean-junos-conf.pl -r examples/example1.conf
./clean-junos-conf.pl -g examples/example2.conf > graph.dot
```

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Authors
- **Pavel Gulchouck** (original author, (https://gul-tech.livejournal.com/9245.html)).
- **evgenyzh** (updates and enhancements).

## Contributing
Contributions are welcome! Please submit issues or pull requests on GitHub.
