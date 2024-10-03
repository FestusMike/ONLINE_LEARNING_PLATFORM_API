def course_file_path(instance, filename):
    return f"courses/{instance.area_of_specialization.name}_{instance.course_title}"