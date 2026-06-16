from typing import Any

from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """
    Base class for all SQLAlchemy declarative models.
    """

    id: Any

    @declared_attr.directive
    def __tablename__(cls) -> str:
        """
        Automatically generate __tablename__ from class name.
        e.g., User -> users, Scan -> scans
        """
        return cls.__name__.lower() + "s"
