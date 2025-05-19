import pandas as pd
import json
import sys
import argparse


def read_excel(input_path, sheet_name=0):
    """Read Excel file into a pandas DataFrame"""
    return pd.read_excel(input_path, sheet_name=sheet_name)


def df_to_json(df, output_path):
    records = df.to_dict(orient='records')
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
    print(f"JSON output written to {output_path}")


def df_to_csv(df, output_path):
    df.to_csv(output_path, index=False)
    print(f"CSV output written to {output_path}")


def df_to_burp_payloads(df, output_path, target, base_url, method='GET', custom_path=None):
    """
    Build Burp payloads for batch import:
      - DVWA: default GET to '/dvwa/vulnerabilities/sqli/'
      - bWAPP: default GET to '/bWAPP/sqli_1.php'
      - custom: use custom_path or build query from all DataFrame columns

    Supports GET and POST. For POST, body is urlencoded from row values.
    """
    lines = []
    host = base_url.split('://')[-1].split('/')[0]

    for _, row in df.iterrows():
        params = '&'.join(f"{k}={v}" for k, v in row.items())
        # determine request path and body
        if target.lower() == 'dvwa':
            endpoint = '/dvwa/vulnerabilities/sqli/'
            key = row.index[0]
            params = f"id={row.iloc[0]}&Submit=Submit"
        elif target.lower() == 'bwapp':
            endpoint = '/bWAPP/sqli_1.php'
            params = f"title={row.iloc[0]}&action=search&form=submit"
        else:
            endpoint = custom_path or ''
        # for GET, append query string
        if method.upper() == 'GET':
            path = f"{endpoint}?{params}" if params else endpoint
        else:
            path = endpoint
        # build raw HTTP request
        req_lines = [
            f"{method.upper()} {path} HTTP/1.1",
            f"Host: {host}",
            "User-Agent: Mozilla/5.0",
            "Accept: */*"
        ]
        # add POST headers and body
        if method.upper() == 'POST':
            req_lines.append("Content-Type: application/x-www-form-urlencoded")
            req_lines.append(f"Content-Length: {len(params.encode('utf-8'))}")
            req_lines.append('')  # blank line before body
            req_lines.append(params)
        # end of request
        req_lines.append('')
        lines.append("\r".join(req_lines))

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("\r".join(lines))
    print(f"Burp payloads written to {output_path} in {target.upper()} mode ({method} requests)")


def main():
    parser = argparse.ArgumentParser(description="Convert Excel payloads to JSON, CSV, and Burp batch format.")
    parser.add_argument('input', help='Path to Excel file')
    parser.add_argument('--sheet', default=0, help='Sheet name or index')
    parser.add_argument('--target', choices=['dvwa', 'bwapp', 'custom'], default='custom',
                        help='Preset target: dvwa, bwapp, or custom')
    parser.add_argument('--base-url', default='http://127.0.0.1', help='Base URL of the target web app')
    parser.add_argument('--method', choices=['GET', 'POST'], default='GET', help='HTTP method for requests')
    parser.add_argument('--path', default='', help='Custom endpoint path (for custom target)')
    parser.add_argument('--out-prefix', default='output', help='Prefix for output files')
    args = parser.parse_args()

    df = read_excel(args.input, args.sheet)
    df_to_json(df, f"output/{args.out_prefix}.json")
    df_to_csv(df, f"output/{args.out_prefix}.csv")
    df_to_burp_payloads(
        df,
        f"output/{args.out_prefix}_burp.txt",
        target=args.target,
        base_url=args.base_url,
        method=args.method,
        custom_path=args.path
    )

if __name__ == '__main__':
    main()