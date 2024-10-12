"""
author: Dominik Cedro
team: Znamy sie tylko z widzenia!
date: 12.10.2024
"""
from fastapi import FastAPI

app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/hello/{name}")
async def say_hello(name: str):
    return {"message": f"Hello {name}"}
