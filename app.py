from flask import Flask, request, jsonify, render_template
import boto3
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Your Cognito details
COGNITO_REGION = "ap-southeast-2"
COGNITO_USER_POOL_ID = "ap-southeast-2_hczmFu5Rv"
COGNITO_CLIENT_ID = "6v98tbc09aqfvh52fml3usas3c"

# Reuse the boto3 client
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
        return jsonify({"error": "Invalid username or password"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500
