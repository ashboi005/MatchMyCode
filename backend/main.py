from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    '''This is the first and default route for the MatchMyCode Backend'''
    return {"message": "Hello World!"}

