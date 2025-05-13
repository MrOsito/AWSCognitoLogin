from flask import Flask, request, jsonify, render_template
import boto3
import jwt
import requests

app = Flask(__name__)

COGNITO_REGION = "ap-southeast-2"
COGNITO_USER_POOL_ID = "ap-southeast-2_hczmFu5Rv"
COGNITO_CLIENT_ID = "6v98tbc09aqfvh52fml3usas3c"

cognito_client = boto3.client("cognito-idp", region_name=COGNITO_REGION)

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/flask-login", methods=["POST"])
def flask_login():
    data = request.get_json()
    try:
        response = cognito_client.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            ClientId=COGNITO_CLIENT_ID,
            AuthParameters={
                "USERNAME": data["username"],
                "PASSWORD": data["password"]
            }
        )
        id_token = response["AuthenticationResult"]["IdToken"]
        return jsonify({"id_token": id_token})
    except cognito_client.exceptions.NotAuthorizedException:
        return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/validate-token", methods=["POST"])
def validate_token():
    token = request.headers.get("Authorization")
    try:
        # Get public keys from Cognito JWKS
        jwks_url = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
        jwks = requests.get(jwks_url).json()
        headers = jwt.get_unverified_header(token)
        key = next(k for k in jwks["keys"] if k["kid"] == headers["kid"])
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)

        claims = jwt.decode(token, public_key, algorithms=["RS256"], audience=COGNITO_CLIENT_ID)
        return jsonify({"claims": claims})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
