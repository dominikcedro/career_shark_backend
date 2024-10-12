"""
author: Dominik Cedro
team: Znamy sie tylko z widzenia!
date: 12.10.2024
"""

# from dotenv import load_dotenv
import os
from typing import Optional, List
import bson
from icecream import ic
import jwt
from fastapi import Depends, FastAPI, Request
from pydantic import BaseModel, EmailStr
from pymongo.mongo_client import MongoClient
from dotenv import load_dotenv
from bson import ObjectId
from fastapi import Body, HTTPException, status
from jwt.exceptions import InvalidTokenError
from datetime import timedelta
from fastapi import Request
from starlette.middleware.cors import CORSMiddleware

# module imports
from models import User, UserCreate, UserInDB, Token, TokenData, LoginRequest, RegisterRequest, UserResponse, \
    RefreshRequest, TokenRequest, LessonResponse, LessonCreate, Quiz
from security import get_password_hash, verify_password, oauth2_scheme, SECRET_KEY, ALGORITHM, \
    ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token, REFRESH_TOKEN_EXPIRE_MINUTES, create_refresh_token

load_dotenv()

# DB setup
uri = os.getenv("MONGO_URI")
client = MongoClient(uri)
db = client.carrershark
collection_users = db["users"]
collection_counters = db["counters"]
collection_lessons = db["lessons"]

# API setup
app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def validate_user_create(request: Request):
    """
    util function for validating if email is in correct form
    :param request: request body to validate
    """
    body = await request.json()
    email = body.get("email")
    if not email or "@" not in email or "." not in email.split("@")[1]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email address. An email address must have an @-sign and a period after the @-sign."
        )
    return body


def add_user_to_db(collection, user: UserCreate):
    """
    Add user to database.

    Args:
        collection (Collection): The database collection to query.
        user (UserCreate): The dto for user

    Returns:
        UserinDB: a representation of user in DB with hashed passwords and PESEL

    Raises:
        HTTP Exception 500 if registration failed
    """
    user_dict = user.dict()
    user_dict["lives"] = 0  # Default value
    user_dict["points"] = 0  # Default value
    user_dict["finished_courses"] = []  # Default value
    result = collection.insert_one(user_dict)
    if result.inserted_id:
        user_dict["_id"] = str(result.inserted_id)
        return UserInDB(**user_dict)
    else:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User registration failed")


def get_user(collection, email: str):
    """
    get user based on email
    """
    user_dict = collection.find_one({"email": email})
    if user_dict:
        user_dict["_id"] = str(user_dict["_id"])
        return UserInDB(**user_dict)
    return None


def authenticate_user(collection, email: EmailStr, password: str):
    """
    Verify email and password credentials of a user.

    Args:
        collection (Collection): The database collection to query.
        email (EmailStr): The email address of the user.
        password (str): The password of the user.

    Returns:
        dict or bool: The user dictionary if authentication is successful,
        otherwise False.
    """
    user = get_user(collection, email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def get_user_by_id(collection, user_id: str):
    """
        Retrieve user from db based on user_id - BSON

        Args:
            collection (Collection): The database collection to query.
            user_id (str): The id of the user.

        Returns:
            UserResponse: full information about user excluding pesel, hashed password

        Raises:
            HTTP Exception 400 when invalid ID format
            HTTP Exception 404 when user not found
        """
    ic("user id here is")
    ic(user_id)
    try:
        user_dict = collection.find_one({"_id": ObjectId(user_id)})
    except bson.errors.InvalidId:
        ic("Invalid user ID format")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user ID format")
    if user_dict:
        user_dict["_id"] = str(user_dict["_id"])
        return UserResponse(**user_dict)
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

@app.post("/login", response_model=Token)
async def login_for_access_token(
    login_request: LoginRequest = Body(...),
) -> Token:
    """
         Login fo access token and refresh token

        Args:
             login_request (LoginRequest): form of email + plain txt password

        Returns:
             Token: access and refresh tokens in json format

    """
    user = authenticate_user(collection_users, login_request.email, login_request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "user_id": user.id}, expires_delta=access_token_expires)

    refresh_token_expires = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    refresh_token = create_refresh_token(data={"user_id": user.id}, expires_delta=refresh_token_expires)
    return Token(access_token=access_token, refresh_token=refresh_token)


@app.post("/register", response_model=Token)
async def register_new_user(register_request: RegisterRequest):
    """
        Register new user to db

        Args:
            register_request (RegisterRequest): register dto

        Returns:
            Token: access_token and refresh_token

        Raises:
            HTTP Exception 400 when email/pesel already registered.
        """
    if get_user(collection_users, register_request.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    hashed_password = get_password_hash(register_request.password)
    new_user = UserCreate(
        email=register_request.email,
        hashed_password=hashed_password,
        DoB=register_request.DoB,
        nickname=register_request.nickname,
        role="USER"
    )
    added_user = add_user_to_db(collection_users, new_user)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": added_user.email, "user_id": added_user.id},
        expires_delta=access_token_expires)

    refresh_token_expires = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    refresh_token = create_refresh_token(data={"user_id": added_user.id}, expires_delta=refresh_token_expires)
    return Token(access_token=access_token, refresh_token=refresh_token)


@app.get("/users/{user_id}", response_model=UserResponse)
async def read_user_by_id(user_id):
    """
        Get specific user by his id as param in url

        Args:
            user_id : id of user in str form

        Returns:
            user (UserResponse): basic information about user exculing hashed password

        Raises:
            HTTP Exception 404 when user not found.
     """
    user = get_user_by_id(collection_users, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user



@app.post("/refresh", response_model=Token)
async def refresh_access_token(refresh_request: RefreshRequest = Body(...)):
    """
        Refresh users access token based on his refresh token

        Args:
            refresh_request(RegisterRequest) : access token in json body (shouldnt be like that)

        Returns:
            Token (Token): access + refresh token

        Raises:
            HTTP Exception 401 UNAUTHORIZED when credentials not validated.
     """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        token = refresh_request.refresh_token
        if not token:
            ic("not token")
            raise credentials_exception
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        if user_id is None:
            ic("user_id is None")
            raise credentials_exception
    except InvalidTokenError:
        ic("invalid token")

        raise credentials_exception

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": payload.get("sub"), "user_id": user_id}, expires_delta=access_token_expires)

    return Token(access_token=access_token, refresh_token=token)


def extract_user_id_from_token(token: str) -> str:
    """
        Util function to retrieve user_id from jwt

        Args:
            token (str):  token

        Returns:
            user_id (str): id of user

        Raises:
            HTTP Exception 401 if user id is not existent or invalid token.
     """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        ic("Extracted user_id from token:", user_id)
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user_id
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.post("/get_me", response_model=UserResponse)
async def extract_user_info(token_request: TokenRequest = Body(...)):
    """
        Get current user information based on jwt token

        Args:
            token_request (TokenRequest):  jwt token in json body

        Returns:
            user (UserResponse): information about user

        Raises:
            HTTP Exception 404 if user id is not existent.
     """
    token = token_request.access_token
    user_id = extract_user_id_from_token(token)
    user = get_user_by_id(collection_users, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.get("/users", response_model=List[UserResponse])
async def get_all_users():
    """
        Get current all users information ONLY FOR ADMINS

        Args:

        Returns:
            list_o_users (List[UserResponse]): information of all users in db

     """
    users = list(collection_users.find({}))
    for user in users:
        user["_id"] = str(user["_id"])
    return [UserResponse(**user) for user in users]


@app.get("/health")
async def healthcheck():
    """
        healthcheck endpoint
    """
    return {"healthcheck": "positive"}


@app.get("/")
async def welcome():
    """
        identification endpoint
    """
    return {"CarrerShark": "ONLINE"}

### lessons endpoints
@app.post("/lessons", response_model=LessonResponse)
async def add_lesson(lesson: LessonCreate): # TODO later make it accept access token so it validates if users has role=EDUCATOR
    """
    Add a new lesson to the database.

    Args:
        lesson (LessonCreate): The lesson data to be added.

    Returns:
        LessonResponse: The added lesson data.
    """
    lesson_dict = lesson.dict()
    result = collection_lessons.insert_one(lesson_dict)
    if result.inserted_id:
        lesson_dict["_id"] = str(result.inserted_id)
        return LessonResponse(**lesson_dict)
    else:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Lesson creation failed")
# get all courses possible (just for fun)
@app.get("/lessons", response_model=List[LessonResponse])
async def get_all_lessons():
    """
    Get all lessons from the database.

    Returns:
        List[LessonResponse]: A list of all lessons.
    """
    lessons = list(collection_lessons.find({}))
    for lesson in lessons:
        lesson["_id"] = str(lesson["_id"])
    return [LessonResponse(**lesson) for lesson in lessons]
# get course ID

# get all courses for set level, check if user has finished any of them, if yes then add
@app.get("/lessons/level/{level}", response_model=List[LessonResponse])
async def get_lessons_by_level(level: int, token: str):
    """
    Get all lessons for a specific level and check if the user has finished any of them.

    Args:
        level (int): The level of the lessons to retrieve.
        token (str): The JWT token of the user.

    Returns:
        List[LessonResponse]: A list of lessons for the specified level with finished status.
    """
    # payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    # user_id: str = payload.get("user_id")
    user_id = extract_user_id_from_token(token)
    user = get_user_by_id(collection_users, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    finished_courses = user.finished_courses
    lessons = list(collection_lessons.find({"level": level}))
    for lesson in lessons:
        lesson["_id"] = str(lesson["_id"])
        lesson["finished"] = 1 if lesson["_id"] in finished_courses else 0

    return [LessonResponse(**lesson) for lesson in lessons]

@app.post("/users/finish_course")
async def finish_course(course_id: str, token: str):
    """
    Add a course ID to the current user's finished courses.

    Args:
        course_id (str): The ID of the course to add.
        token (str): The JWT token of the user.

    Returns:
        dict: A message indicating the course was added to finished courses.
    """
    user_id = extract_user_id_from_token(token)
    user = get_user_by_id(collection_users, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if course_id not in user.finished_courses:
        user.finished_courses.append(course_id)
        collection_users.update_one({"_id": ObjectId(user_id)}, {"$set": {"finished_courses": user.finished_courses}})
        return {"message": "Course added to finished courses"}
    else:
        return {"message": "Course already in finished courses"}

# now lets think about how to retrieve and upload quizz
@app.get("/lessons/{lesson_id}/quiz", response_model=Quiz)
async def get_quiz(lesson_id: str):
    """
    Retrieve the quiz for a specific lesson.

    Args:
        lesson_id (str): The ID of the lesson.

    Returns:
        Quiz: The quiz data for the lesson.
    """
    lesson = collection_lessons.find_one({"_id": ObjectId(lesson_id)})
    if not lesson or not lesson.get("quiz"):
        raise HTTPException(status_code=404, detail="Lesson or quiz not found")

    return Quiz(**lesson["quiz"])

@app.post("/lessons/{lesson_id}/quiz", response_model=LessonResponse)
async def upload_quiz(lesson_id: str, quiz: Quiz):
    """
    Upload a quiz for a specific lesson.

    Args:
        lesson_id (str): The ID of the lesson.
        quiz (Quiz): The quiz data to be uploaded.

    Returns:
        LessonResponse: The updated lesson data with the quiz.
    """
    result = collection_lessons.update_one(
        {"_id": ObjectId(lesson_id)},
        {"$set": {"quiz": quiz.dict()}}
    )
    if result.modified_count == 1:
        lesson = collection_lessons.find_one({"_id": ObjectId(lesson_id)})
        lesson["_id"] = str(lesson["_id"])
        return LessonResponse(**lesson)
    else:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Quiz upload failed")
