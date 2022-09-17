pub fn calculate_factor(starting_value: usize, ending_value: usize) -> f32 {
    let difference = ending_value as f32 - starting_value as f32;
    let average = starting_value + ending_value;
    difference / average as f32
}
