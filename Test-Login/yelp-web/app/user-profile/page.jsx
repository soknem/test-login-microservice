'use client'

import {useState} from "react";

export default function Page() {

    const [profile, setProfile] = useState([]);

    const loadProfile = () => {
        fetch('/profile')
            .then(res => res.json())
            .then(data => {
                console.log(data)
                setProfile(data)
            })
    }

    return (
        <>
            <h1>My Profile</h1>
            <button onClick={loadProfile}>Load Profile</button>
            <hr/>
            <h1>{profile.id}</h1>
    
        </>
    )
}