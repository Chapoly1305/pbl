# Build Instructions

## Compile libpbl.so

The build process requires two steps:

1. **Build the PBL library** (in `src/` directory):
   ```bash
   cd ./src
   make python    # Creates libpbl.a and libpbl.so, copies libpbl.so to parent dir
   ```
   - Creates `libpbl.a` (static library)
   - Creates `libpbl.so` (shared library with platform-specific linking)
   - Copies `libpbl.so` to the project root directory

2. **Build the main tools** (in project root):
   ```bash
   cd ../
   make           # Builds pbl_dat_dump and other utilities
   ```
   - Verifies `libpbl.so` exists
   - Builds the Aqara property database tools

## Platform Support
The build system automatically detects macOS vs Linux and uses appropriate linker flags:
- **macOS**: Uses direct object linking (avoiding `--whole-archive`)
- **Linux**: Uses GNU linker flags (`--whole-archive`/`--no-whole-archive`)

# Run 
## Aqara M2 Hub
TBD
## Aqara M3 Hub / G3 Hub
1. Get a clone image of factory partition
2. python3 ./aqara_property_db_editor.py -r ./p3.img


