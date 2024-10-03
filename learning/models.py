from django.db import models
from django.contrib.auth import get_user_model
from utils.models import BaseModel
from .utils import course_file_path
# Create your models here.

User = get_user_model()

class Specialization(BaseModel):
    name = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    

class Course(BaseModel):
    specialization = models.ForeignKey(Specialization, null=True, on_delete=models.SET_NULL, related_name="related_courses")
    course_title = models.CharField(max_length=255)
    course_description = models.TextField()
    course_duration = models.DurationField()
    course_file = models.FileField(upload_to=course_file_path) 
    price = models.DecimalField(max_digits=10, decimal_places=2)
    tutor = models.ForeignKey(User, on_delete=models.CASCADE, related_name='courses')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.course_title


class Enrollment(BaseModel):
    student = models.ForeignKey(User, on_delete=models.CASCADE, related_name='enrollments')
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='enrollments')
    enrollment_date = models.DateTimeField(auto_now_add=True)
    course_completion_date = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f"{self.student.username} enrolled in {self.course.course_title}"


class Quiz(BaseModel):
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='quizzes')
    quiz_title = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "Quizzes"
        verbose_name_plural = "Quizzes"
    
    def __str__(self):
        return self.quiz_title


class Question(BaseModel):
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE, related_name='questions')
    question_text = models.TextField()
    option_a = models.CharField(max_length=255)
    option_b = models.CharField(max_length=255)
    option_c = models.CharField(max_length=255)
    option_d = models.CharField(max_length=255)
    correct_answer = models.CharField(max_length=1) 

    def __str__(self):
        return self.question_text


class Submission(BaseModel):
    student = models.ForeignKey(User, on_delete=models.CASCADE, related_name='submissions')
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE, related_name='submissions')
    submission_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Submission by {self.student.username} for {self.quiz.quiz_title}"


class AnswerSubmission(BaseModel):
    submission = models.ForeignKey(Submission, on_delete=models.CASCADE, related_name='answers')
    question = models.ForeignKey(Question, on_delete=models.CASCADE, related_name='answer_submissions')
    selected_answer = models.CharField(max_length=1) 
    is_correct = models.BooleanField(default=False)

    def __str__(self):
        return f"Answer to {self.question.question_text}: {self.selected_answer}"

    def save(self, *args, **kwargs):
        if self.selected_answer == self.question.correct_answer:
            self.is_correct = True
        else:
            self.is_correct = False
        super().save(*args, **kwargs)


class Score(BaseModel):
    submission = models.OneToOneField(Submission, on_delete=models.CASCADE, related_name='score')
    score = models.IntegerField()

    def __str__(self):
        return f"Score: {self.score}"

    def save(self, *args, **kwargs):
        correct_answers = self.submission.answers.filter(is_correct=True).count()
        self.score = correct_answers
        super().save(*args, **kwargs)


class Payment(BaseModel):
    student = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payments')
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='payments')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_date = models.DateTimeField(auto_now_add=True)
    payment_status = models.CharField(max_length=20, choices=[("PENDING","Pending"), ("COMPLETED","Completed")]) 

    def __str__(self):
        return f"Payment by {self.student.first_name}_{self.student.last_name} for {self.course.course_title}"
