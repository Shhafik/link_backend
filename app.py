from flask import Flask, request, jsonify, send_from_directory
import requests
import os

app = Flask(__name__)

API_KEY = '16d59b744a312d3f0663878c9724e9de9f966170555020d4e94874b078def4b2'  # replace with your real VirusTotal API key
API_URL = 'https://www.virustotal.com/api/v3/urls'


@app.route('/')
def serve_html():
    return send_from_directory('.', 'index.html')


@app.route('/style.css')
def serve_css():
    return send_from_directory('.', 'style.css')


@app.route('/script.js')
def serve_js():
    return send_from_directory('.', 'script.js')


@app.route('/check', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url') if data else None
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    headers = {'x-apikey': API_KEY, 'Content-Type': 'application/x-www-form-urlencoded'}

    # Step 1: Submit URL
    response = requests.post(API_URL, headers=headers, data=f'url={url}')
    if response.status_code not in [200, 201]:
        return jsonify({'error': 'Failed to submit URL to VirusTotal'}), 500

    analysis_id = response.json().get('data', {}).get('id')
    if not analysis_id:
        return jsonify({'error': 'No analysis ID returned from VirusTotal'}), 500


    # Step 2: Get analysis
    analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    analysis_response = requests.get(analysis_url, headers={'x-apikey': API_KEY})
    if analysis_response.status_code != 200:
        return jsonify({'error': 'Failed to fetch analysis report'}), 500

    stats = analysis_response.json().get('data', {}).get('attributes', {}).get('stats', {})
    return jsonify({
        'harmless': stats.get('harmless', 0),
        'malicious': stats.get('malicious', 0),
        'suspicious': stats.get('suspicious', 0),
        'undetected': stats.get('undetected', 0)
    })


if __name__ == '__main__':
    app.run(debug=True, port=5500)
