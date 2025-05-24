# gymapi
api design for a gym app


## commands to run in order to setup dependecies 

pip install -r requirements.txt

## commands to init and setup the db annd run the app
## postgres db should be setup and initiated before running these 

flask db init
flask db migrate
flask db upgrade
flask run

## admin functionalities will be available after appliying flow below

Get a fresh token from /auth/login (ADMIN123, password: admin123)
Copy the token value
Click 🔒 Authorize in Swagger
Enter: Bearer YOUR_TOKEN_HERE (with the word "Bearer" and a space)
Try the request again