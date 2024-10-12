"""
author: Dominik Cedro
team: Znamy sie tylko z widzenia!
date: 12.10.2024
"""
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field
from bson import ObjectId
from pydantic import BaseModel, EmailStr
from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    refresh_token: str


class TokenData(BaseModel):
    email: EmailStr | None = None


class User(BaseModel):
    email: EmailStr
    DoB: str
    nickname: str
    role: str
    # disabled was deleted is it okay?
    lives: int
    points: int
    finished_courses: list[str]


class UserCreate(BaseModel):
    email: EmailStr
    nickname: str
    DoB: str
    role: str = "USER"
    hashed_password: str



class UserInDB(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    email: EmailStr
    hashed_password: str
    DoB: str
    nickname: str
    role: str
    lives: int = 0  # Default value
    points: int = 0  # Default value
    finished_courses: List[str] = []  # Default value

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }


class UserResponse(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    email: EmailStr
    DoB: str
    nickname: str
    role: str
    lives: int
    points: int
    finished_courses: List[str]

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RegisterRequest(BaseModel):
    email: EmailStr
    nickname: str
    DoB: str
    role: str = "USER"
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenRequest(BaseModel):
    access_token: str

### LESSONS


class Lesson(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    name: str
    level: int
    link_to_resources: str
    test: str  # Accepting a string for now
    value_points: int

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }


class LessonCreate(BaseModel):
    name: str
    level: int
    link_to_resources: str
    test: str  # Accepting a string for now
    value_points: int


class LessonResponse(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    name: str
    level: int
    link_to_resources: str
    test: str  # Accepting a string for now
    value_points: int
    finished: int = 0 # zero for not finished, 1 for finished for current user

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }