from database import Base, engine

print("Creating tables in the database...")
# Lệnh này sẽ đọc tất cả các class kế thừa từ Base và tạo bảng tương ứng
Base.metadata.create_all(bind=engine)
print("Tables created successfully.")