# BinaryX-IDA

Export comprehensive binary analysis data from IDA Pro to JSON format for Neo4j graph database visualization and analysis.

## Features

The information included in binary file parsing consists of

* Binary Information
* Function Analysis
* Call Relationship Detection: direct / indirect / tail / callback
* String Extraction

## Usage

Prerequisites:

* **IDA Pro 9.0+** with Python support
* **Python 3.11+** (bundled with IDA Pro)

You should have IDA Pro installed and Python 3.11+ available in your system.Then you can import the generated data into the BinaryX-Graph.

```bash
# Basic usage
python src/main.py -f binary.exe -o output.json

# With custom string length filter
python src/main.py -f sample.dll -o output.json --min-string-length 6
```

## Output Format

```json
{
  "binary_info": {
    "name": "",
    "file_path": "",
    "file_size": ,
    "file_type": {
      "type": "",
      "architecture": ""
    },
    "hashes": {
      "sha256": ""
    }
  },
  "functions": [
    {
      "name": "",
      "address": "",
      "size": 
    }
  ],
  "imports": [
    {
      "name": "",
      "address": "",
      "library": ""
    }
  ],
  "exports": [
    {
      "name": "",
      "address": "",
      "ordinal": 
    }
  ],
  "strings": [
    {
      "value": "",
      "address": "",
      "length": ,
      "type": ""
    }
  ],
  "calls": [
    {
      "from_address": "",
      "to_address": "",
      "offset": "",
      "type": ""
    }
  ]
}
```

Call Types:

| Type | Description | Example |
|------|-------------|---------|
| `direct` | Direct function call | `call 0x401000` |
| `indirect` | Call through register/memory | `call rax`, `call [rip+0x1000]` |
| `tail` | Tail call optimization (JMP to function) | `jmp func` |
| `callback` | Function address passed as parameter | `lea rsi, func` |

## Changelog

See [CHANGELOG.md](CHANGELOG.md)

## TODO

- [ ] Classify functions according to their complexity
- [ ] Enhanced Invocation analysis
- [ ] Batch processing

## Contact

 **Issues**: [GitHub Issues](https://github.com/waiwai24/BinaryX-IDA/issues/new)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
