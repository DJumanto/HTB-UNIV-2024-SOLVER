numbers_as_strings = [f"{num:04}" for num in range(1000, 10000)]

# Print the array
with open("out.txt", "w") as f:
    f.write(str(numbers_as_strings))