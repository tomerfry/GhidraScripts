#include <stdio.h>
#include <malloc.h>


typedef struct Person {
    int age;
    int license_number;
    char *name;
} person_t;

person_t *create_person(int age, int license_number, char *name);
void check_license_for_new_person(int redos);

int main(int argc, char **argv) {
    check_license_for_new_person(10);
}

void check_license_for_new_person(int redos){
    person_t *jay = create_person(16, 11, "will");
    person_t *john = create_person(17, 11, "will");
    free(john);
    person_t *will = create_person(15, 11, "will");
    

    printf("Hello %s", will->name);
    for (int i=0; i<redos; ++i){
        if (will->license_number % 2 == 1)
            printf("Your license is odd numbered: %d", will->license_number);
        else
            printf("Your license is even numbered: %d", will->license_number);
    }
}

person_t *create_person(int age, int license_number, char *name) {
    person_t *new_person = malloc(sizeof(person_t));
    new_person->age = age;
    new_person->name = name;

    if (age < 16) 
        return new_person;

    new_person->license_number = license_number;
    return new_person;
}
