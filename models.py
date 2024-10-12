"""
author: Dominik Cedro
team: Znamy sie tylko z widzenia!
date: 12.10.2024
"""
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field, root_validator
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
### quizzes


class Choice(BaseModel):
    option: str
    text: str

class Question(BaseModel):
    question_text: str
    choices: List[Choice]
    correct_option: str # a / b / c lowercase

class Quiz(BaseModel):
    name_of_test: str
    to_pass: int
    num_of_questions: int
    questions: List[Question]

class QuizUploadRequest(BaseModel):
    name_of_test: str
    to_pass: int = 50
    num_of_questions: int = 0
    questions: List[Question]

    @root_validator(pre=True)
    def set_num_of_questions(cls, values):
        questions = values.get('questions', [])
        values['num_of_questions'] = len(questions)
        if 'to_pass' not in values:
            values['to_pass'] = 50
        return values

### LESSONS


class Lesson(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    name: str
    level: int
    link_to_resources: str
    value_points: int
    quiz: Optional[Quiz] = None

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }


class LessonCreate(BaseModel):
    name: str
    level: int
    link_to_resources: str
    quiz: Optional[Quiz] = None
    value_points: int


class LessonResponse(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    name: str
    level: int
    link_to_resources: str
    quiz: Optional[Quiz] = None
    value_points: int
    finished: int = 0 # zero for not finished, 1 for finished for current user

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }


class FinishQuizRequest(BaseModel):
    answers: List[str]

### classes for leaderboards

class LeaderBoard(BaseModel):
    user_id: str
    nickname: str
    score: int
    courses: List[str]
