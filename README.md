# Traceroute OSINT Tool

Advanced network path analysis and OSINT gathering tool for NexusHub.

## Features

- **Network Path Analysis**: Perform traceroute to any host or IP address
- **OSINT Gathering**: Collect DNS, WHOIS, geolocation, and ASN information
- **Security Analysis**: Identify potential security concerns in network paths
- **Port Scanning**: Basic port scanning for common services
- **Geographic Visualization**: View network path on a geographic map
- **Export Options**: Export results in JSON, CSV, or TXT formats

## Usage

### Basic Traceroute
1. Enter a target hostname or IP address
2. Configure maximum hops and timeout settings
3. Click "Start Traceroute" to begin analysis

### Advanced Options
- **Port Scanning**: Choose between basic, extended, or no port scanning
- **OSINT Level**: Select the level of OSINT data collection
- **Analysis Type**: Choose security, performance, geographic, or comprehensive analysis
- **Alert Level**: Set the sensitivity for security alerts

## Python Dependencies

Install required Python packages:

```bash
pip install -r requirements.txt
```

### Required Packages
- `requests`: HTTP library for API calls
- `python-whois`: WHOIS information lookup
- `dnspython`: DNS toolkit
- `geoip2`: GeoIP database access
- `ipaddress`: IP address manipulation

## Configuration

### GeoIP Database
For full geolocation functionality, download the GeoLite2 database:
1. Visit https://dev.maxmind.com/geoip/geoip2/geolite2/
2. Download the GeoLite2-City.mmdb file
3. Place it in the tool directory

### Custom Ports
Add custom ports for scanning by entering comma-separated values in the "Custom Ports" field.

## Security Features

- **Port Analysis**: Identifies open ports and potential security risks
- **Private IP Detection**: Alerts on private IPs in public routes
- **Organization Tracking**: Maps network path through different organizations
- **Geographic Analysis**: Identifies routing through unexpected countries

## Export Formats

### JSON
Complete structured data including all OSINT information and analysis results.

### CSV
Tabular format with hop-by-hop details for spreadsheet analysis.

### TXT
Human-readable text format for reports and documentation.

## Network Requirements

- Internet connection for external lookups
- Administrative privileges may be required for traceroute on some systems
- Firewall may need to allow outbound connections for port scanning

## Limitations

- Traceroute requires system-level access
- Some networks may block traceroute packets
- GeoIP accuracy depends on database quality
- WHOIS data may be incomplete or outdated

## Troubleshooting

### Common Issues
1. **Permission Denied**: Run with administrative privileges
2. **No Route to Host**: Check network connectivity and firewall settings
3. **GeoIP Errors**: Ensure GeoLite2 database is properly installed
4. **WHOIS Failures**: Some registrars may block automated queries

### Debug Mode
Enable debug logging by setting environment variable:
```bash
export TRACEROUTE_DEBUG=1
```

## Contributing

To add new features or improve the tool:
1. Fork the repository
2. Create a feature branch
3. Implement changes
4. Test thoroughly
5. Submit a pull request

## License

This tool is part of NexusHub and follows the same licensing terms. 