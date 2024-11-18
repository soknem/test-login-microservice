'use client'

import {useState} from "react";

export default function Page() {

    const [category, setCategory] = useState([]);

    const loadCategory = () => {
        fetch('/api/v1/categories')
            .then(res => res.json())
            .then(data => {
                console.log(data)
                setCategory(data)
            })
    }

    return (
        <>
            <h1>Category Page</h1>
            <button onClick={loadCategory}>Load Category</button>
            <hr/>
            <h1>{category.name}</h1>
        </>
    )
}