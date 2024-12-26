from app import db, bcrypt, create_app
from app.models import User

# Create an application context
app = create_app()
with app.app_context():
    # Hash the password
    hashed_password = bcrypt.generate_password_hash("<your_admin_password>").decode('utf-8')

    # Create the admin user
    admin_user = User(
        username='<admin_username>',
        email='<your_admin_email>',
        password=hashed_password,
        is_admin=True
    )
    db.session.add(admin_user)
    db.session.commit()
    print("Admin user created successfully!")
