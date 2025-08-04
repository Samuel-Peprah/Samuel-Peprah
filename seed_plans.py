# seed_plans.py
from app import app, db
from app import User, Plan  # adjust if models are in a submodule

def seed_users():
    users = [
        {"username": "admin", "email": "admin@activot.com", "role": "admin", "password": "admin123"},
        {"username": "therapist", "email": "therapist@activot.com", "role": "therapist", "password": "therapist123"},
        {"username": "client", "email": "client@activot.com", "role": "client", "password": "client123"}
    ]

    for u in users:
        if not User.query.filter_by(username=u["username"]).first():
            user = User(username=u["username"], email=u["email"], role=u["role"])
            user.set_password(u["password"])
            db.session.add(user)
            print(f"✅ Created user: {u['username']}")

def seed_plans():
    plans_data = [
        # Client Plans
        {"name": "Client Monthly Plan", "amount_pesewas": 5000, "interval_days": 30,
         "description": "Full access for clients for one month.", "for_role": "client", "is_active": True},
        {"name": "Client Quarterly Plan", "amount_pesewas": 12000, "interval_days": 90,
         "description": "Extended access for clients for three months.", "for_role": "client", "is_active": True},
        {"name": "Client Annual Plan", "amount_pesewas": 40000, "interval_days": 365,
         "description": "Premium access for clients for one year.", "for_role": "client", "is_active": True},
        # Therapist Plans
        {"name": "Therapist Monthly Plan", "amount_pesewas": 3000, "interval_days": 30,
         "description": "Access to therapist features for one month.", "for_role": "therapist", "is_active": True},
        {"name": "Therapist Quarterly Plan", "amount_pesewas": 7500, "interval_days": 90,
         "description": "Extended access to therapist features for three months.", "for_role": "therapist", "is_active": True},
        {"name": "Therapist Annual Plan", "amount_pesewas": 25000, "interval_days": 365,
         "description": "Full access to therapist features for one year.", "for_role": "therapist", "is_active": True},
    ]

    for data in plans_data:
        existing = Plan.query.filter_by(name=data["name"]).first()
        if existing:
            existing.amount_pesewas = data["amount_pesewas"]
            existing.interval_days = data["interval_days"]
            existing.description = data["description"]
            existing.for_role = data["for_role"]
            existing.is_active = data["is_active"]
            print(f"🔁 Updated plan: {data['name']}")
        else:
            new_plan = Plan(**data)
            db.session.add(new_plan)
            print(f"✅ Created plan: {data['name']}")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        seed_users()
        db.session.commit()
        print("✅ Users committed.")

        seed_plans()
        db.session.commit()
        print("✅ Plans table synced.")