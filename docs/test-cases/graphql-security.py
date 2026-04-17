"""GraphQL security — intentionally vulnerable. DO NOT deploy."""
import strawberry
from strawberry.fastapi import GraphQLRouter
from fastapi import FastAPI

@strawberry.type
class User:
    id: int
    name: str
    @strawberry.field
    def friends(self) -> list["User"]:
        return []  # in real code, this would query the DB
    @strawberry.field
    def posts(self) -> list["Post"]:
        return []

@strawberry.type
class Post:
    id: int
    body: str
    @strawberry.field
    def author(self) -> User:
        return User(id=1, name="test")
    @strawberry.field
    def comments(self) -> list["Comment"]:
        return []

@strawberry.type
class Comment:
    id: int
    text: str

@strawberry.type
class Query:
    @strawberry.field
    def user(self, id: int) -> User:
        return User(id=id, name="test")

# BUG: no depth limit, no cost analysis, introspection enabled
schema = strawberry.Schema(query=Query)

app = FastAPI()
app.include_router(GraphQLRouter(schema), prefix="/graphql")
