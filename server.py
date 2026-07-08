from flask import Flask, request, jsonify
from flask_cors import CORS
from agent import run_agent

app = Flask(__name__)
CORS(app)

@app.route("/analyse", methods=["POST"])
def analyse():
    data = request.json
    address = data["address"]
    result = run_agent(address)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True, port=5000)