from flask import Flask, render_template, jsonify
from system_monitor import get_system_stats

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/system_stats')
def system_stats():
    return jsonify(get_system_stats())

if __name__ == '__main__':
    app.run(debug=True)
