@javascript
Feature: Member profiles are displayed on index page

    As a visitor
    In order to be able to browse through Member profiles
    I would like to be able to see a paginated collection of member profiles on the index page of the platform


    Background:
        Given the following users exists
            | email              | first_name | last_name | role   |
            | alumni_1@craft.com | Student    | One       | member |
            | alumni_2@craft.com | Student    | Two       | member |
            | alumni_3@craft.com |            |           | member |
            | coach_1@craft.com  | Head       | Coach     | coach  |


    Scenario: Member profiles are displayed on index page
        When a visitor visits the site
        Then he should see "Student One" in "members" section
        And he should see "Student Two" in "members" section
        And he should see "alumni_3@craft.com" in "members" section
        And he should not see "Head Coach" in "members" section