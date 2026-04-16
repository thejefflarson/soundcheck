# Test case: mass-assignment (API8:2023)
# Django and SQLAlchemy examples of mass assignment
from flask import Flask, request, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

app = Flask(__name__)

# --- Django-style ---
from django.http import JsonResponse

def create_user_django(request):
    data = request.POST.dict()
    # BUG: all request fields passed to create -- attacker can set role=admin
    user = User.objects.create(**data)
    return JsonResponse({"id": user.id})

def update_profile_django(request, user_id):
    body = request.body_json()
    # BUG: unfiltered update -- attacker can set is_verified=True
    User.objects.filter(id=user_id).update(**body)
    return JsonResponse({"ok": True})

# --- SQLAlchemy-style ---
@app.route("/users", methods=["POST"])
def create_user_sqla():
    payload = request.get_json()
    session = Session(bind=engine)
    # BUG: spreading request JSON into model constructor
    user = UserModel(**payload)
    session.add(user)
    session.commit()
    return jsonify({"id": user.id}), 201
