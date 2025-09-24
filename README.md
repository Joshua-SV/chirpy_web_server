# About Me

Chirpy is a small web server that lets you interact with its API endpoints, create user account and store text posts in PostgreSQL via server interaction, The user never interacts with the database directly but only through the http endpoints made available. Chirpy allows for user authentication so that no one else posts or deletes posts not authorized.

# Setup for the Gator RSS

Will need to have **PostgreSQL** and **Go Language** you can check by opening your CLI then typing the commands shown below

- To check if you have postgres use `psql --version` Make sure it is version 16 or higher
- To check if you have Go use `go version` Make sure it is version 1.22 or higher

### installing postgres and Go

If you don't have homebrew installed I recommend it here is the link: [homebrew](https://brew.sh/)
Otherwise just install each through their respective websites

- installing postgres using homebrew: `brew install psql`
- installing go using homebrew: `brew install go`

Once you have both installed you can then get the Gator binary using `go install https://github.com/Joshua-SV/gator`

### run postgres

Make sure PostgreSQL is running on your machine: `brew services start postgresql`

### create the database

Make sure you have the database called gator created:

- open postgres using `psql postgres`
- in the prompt type `CREATE DATABASE chirpy`
- check that gator was created `\l`
- exit psql using `\q`

### run goose

To build up the database we will use goose, make sure you are in the root directory of the gator files

- install goose using `go install github.com/pressly/goose/v3/cmd/goose@latest`
- then type this but modify the "your_name" to your system name `goose -dir ./sql/schema postgres "postgres://your_name:@localhost:5432/chirpy" up`

# How to use Chirpy

since this a web server we need to interact with it using http endpoints which can be done using the CLI (command line interface) or a GUI like Postman.

I will be using CLI `curl` command and here is an example of how you would provide json data to a POST endpoint

### How to use curl

- Here's a common example for sending JSON data to an API endpoint: `curl -X POST -H "Content-Type: application/json" -d '{"name": "Boots", "message": "Hello from Boot.dev!"}' https://api.example.com/data`

Let's break it down:

- curl: The command-line tool.
- -X: Specifies the HTTP method to be used in this example it is POST.
- -H "Content-Type: application/json": Tells the server that the data being sent in the request body is JSON. -H mean that header information will be sent to the server.
- -d '{"name": "Boots", "message": "Hello from Boot.dev!"}': This is the actual JSON data being sent.
- https://api.example.com/data: This is the URL of the endpoint you are sending the POST request to. in this cases your working with your local machine aka your computer is the server therefore use: http://localhost:8080/

### here are the endpoints to use

to use endpoints you must have the domain name prefixed; in our case it is http://localhost:8080/

- `app/` is a `GET` endpoint that will provide you with html, css files that will render the words "Welcome to Chirpy" in a browser.
- `/admin/metrics` is a `GET` endpoint that will display the number of times `app/` endpoint was used.
- `/admin/reset` is a `POST` endpoint that will reset the `/admin/metrics` value and delete all users in the database
- `/api/chirps` has a `GET` and `POST` endpoints:
  - `GET` endpoint returns all the chirps found in the database by returning a JSON structure list, this endpoint allows for two options at the end of the endpoint. to use an option use `?` then to separate options use `&` example `/api/chirps?name_of_option=value`:
    - `author_id=<UUID here>` the author id option is used to filter the chirps and get only the chirps with the author id.
    - `sort=[asc or desc]` the sort option is used to sort chirps in ascend or descend of creation time.
