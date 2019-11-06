import requests
from datetime import date

API_URL = 'https://usuarios.taloo.cl/api/1.0'
API_KEY = 'KTXvLBD7TvoBjVxp9iRyJcJLgWeM3mkS'

# headers = {'X-Api-Key': API_KEY}

# response = requests.get(
#     '{}/files/Andres_Agurto_-_The_Cookie_Factory5.jpg'.format(API_URL), headers=headers
# )

today = date.today()

print(str(today.day) + '-' + str(today.month) + '-' + str(today.year))