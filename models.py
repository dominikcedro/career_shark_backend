"""
original author: Dominik Cedro
created: 2024-09-28
license: none
description: Models for user objects in DB, they also perform DTO role
"""
from typing import Optional
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


class UserInDB(User):
    id: Optional[str] = Field(None, alias="_id")
    hashed_password: str

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
