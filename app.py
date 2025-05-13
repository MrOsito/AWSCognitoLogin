from flask import Flask, render_template, request, jsonify
import boto3
import jwt
from jwt.algorithms import RSAAlgorithm
import requests

app = Flask(__name__)

REGION = "ap-southeast-2"
POOL_ID = "ap-southeast-2_hczmFu5Rv"
CLIENT_ID = "6v98tbc09aqfvh52fml3usas3c"

cognito = boto3.client("cognito-idp", region_name=REGION)

@app.route("/")
def index():
    return render_template("multi_login.html")

@app.route("/flask-login", methods=["POST"])
def flask_login():
    data = request.get_json()
    try:
        auth_result = cognito.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            ClientId=CLIENT_ID,
            AuthParameters={
                "USERNAME": data["username"],
                "PASSWORD": data["password"]
            }
        )
        return jsonify({"id_token": auth_result["AuthenticationResult"]["IdToken"]})
    except Exception as e:
        return jsonify({"error": str(e)}), 401

@app.route("/validate-token", methods=["POST"])
def validate_token():
    token = request.headers.get("Authorization")
    try:
        jwks_url = f"https://cognito-idp.{REGION}.amazonaws.com/{POOL_ID}/.well-known/jwks.json"
        jwks = requests.get(jwks_url).json()
        header = jwt.get_unverified_header(token)
        key = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
        claims = jwt.decode(token, public_key, algorithms=["RS256"], audience=CLIENT_ID)
        return jsonify({"claims": claims})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    app.run(debug=True)
