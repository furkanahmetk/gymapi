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